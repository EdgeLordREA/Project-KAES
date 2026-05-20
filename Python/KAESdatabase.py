import select
import socket
import threading
from mysql.connector import pooling
import mysql.connector
import bcrypt
import paramiko

import SECRETS

#region pooling
# Global references for our single application-level tunnel pipeline and connection pool
_global_transport = None
_local_tunnel_port = None
_connection_pool = None


def _ssh_forwarding_loop(local_socket, ssh_transport, remote_host, remote_port):
    """
    Listens on the local socket. Every time a connection request arrives from the pool,
    it opens a completely separate, concurrent SSH channel over the global transport.
    """
    while True:
        try:
            client_sock, addr = local_socket.accept()
        except Exception:
            break  # Local socket closed or shutting down, exit cleanly

        try:
            # Open a completely distinct channel through the existing SSH session
            chan = ssh_transport.open_channel(
                "direct-tcpip", (remote_host, remote_port), client_sock.getpeername()
            )
            if chan is None:
                client_sock.close()
                continue
        except Exception:
            client_sock.close()
            continue

        # Dedicated bi-directional data forwarding handler for this specific connection channel
        def forward_data(src, dest):
            try:
                while True:
                    # Monitor readability natively
                    readable_sockets, _, _ = select.select([src, dest], [], [])
                    if src in readable_sockets:
                        data = src.recv(4096)
                        if not data:
                            break
                        dest.sendall(data)
                    if dest in readable_sockets:
                        data = dest.recv(4096)
                        if not data:
                            break
                        src.sendall(data)
            except Exception:
                pass
            finally:
                try:
                    src.close()
                except Exception:
                    pass
                try:
                    dest.close()
                except Exception:
                    pass

        threading.Thread(target=forward_data, args=(client_sock, chan), daemon=True).start()


def initialize_global_tunnel():
    """Initializes the native Paramiko transport loop and a MySQL connection pool exactly once."""
    global _global_transport, _local_tunnel_port, _connection_pool
    if _connection_pool is not None:
        return

    try:
        # 1. Connect to SSH Server using up-to-date Paramiko defaults (bypassing outdated DSS/sshtunnel modules)
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ssh_client.connect(
            hostname=SECRETS.SSH_HOST,
            port=22,
            username=SECRETS.SSH_USER,
            password=SECRETS.SSH_PASSWORD
        )

        # Capture and maintain the transport object globally
        _global_transport = ssh_client.get_transport()
        # pyrefly: ignore [missing-attribute]
        _global_transport.set_keepalive(30)  # Prevent firewalls from dropping the idle connection

        # 2. Bind to a dynamic free local port
        local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        local_socket.bind(('127.0.0.1', 0))
        _local_tunnel_port = local_socket.getsockname()[1]
        local_socket.listen(50)

        # 3. Start the non-blocking port forwarder background daemon thread
        forwarding_thread = threading.Thread(
            target=_ssh_forwarding_loop,
            args=(local_socket, _global_transport, SECRETS.SB_HOST, SECRETS.DB_PORT),
            daemon=True
        )
        forwarding_thread.start()

        # 4. Initialize a thread-safe MySQL Connection Pool targeting our dynamic local port
        _connection_pool = mysql.connector.pooling.MySQLConnectionPool(
            pool_name="kaes_pool",
            pool_size=10,  # Allows up to 10 isolated DB worker threads to run simultaneously
            host='127.0.0.1',
            port=_local_tunnel_port,
            user=SECRETS.DB_USERNAME,
            password=SECRETS.DB_PASSWORD,
            database="nbuch"
        )
        print(f"Native SSH Tunnel established on local port {_local_tunnel_port}. Connection pool active.")
    except Exception as error:
        print(f"Critical error initializing global tunnel pipeline: {error}")
        raise
#endregion

# noinspection PyBroadException
class KaesDatabase:
    #region boilerplate
    def __init__(self):
        if _connection_pool is None:
            raise RuntimeError("Database pool has not been initialized. Call initialize_global_tunnel() first.")
        # Seamlessly grab a completely clean, thread-isolated connection from the pool
        self.connection = _connection_pool.get_connection()

    def get_cursor(self, dictionary: bool = False):
        """
        Helper method to quickly grab a cursor.
        Setting dictionary=True returns rows as dicts instead of tuples.
        """
        if not self.connection or not self.connection.is_connected():
            raise RuntimeError("Database connection is not established or lost.")
        return self.connection.cursor(dictionary=dictionary)

    def commit(self):
        """Commit any pending transaction to the database."""
        if not self.connection:
            raise RuntimeError("Database connection is not established.")
        self.connection.commit()

    def close_connection(self):
        """Returns the MySQL connection cleanly back into the global pool without destroying the tunnel."""
        try:
            if self.connection and self.connection.is_connected():
                self.connection.close()  # When pooled, .close() releases it back to the pool
                # pyrefly: ignore [bad-assignment]
                self.connection = None
                print("MySQL connection closed gracefully.")
        except Exception as e:
            print(f"Error closing MySQL connection: {e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_connection()
#endregion

    # region authentication
    def login(self, username: str, password: str) -> bool:
        cursor = self.get_cursor(dictionary=True)
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            return False

        return self._check_password(password, user["password"])

    def _hash_password(self, password: str) -> str:
        """Hash a plaintext password for storage."""
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def _check_password(self, password: str, password_hash: str) -> bool:
        """Check whether a plaintext password matches a stored bcrypt hash."""
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))

    # endregion

    # region users
    def add_user(self, username: str, password: str):
        cursor = self.get_cursor()
        password_hash = self._hash_password(password)

        cursor.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (username, password_hash),
        )
        self.commit()

    def get_all_users(self):
        """Fetches all users and their associated permissions."""
        cursor = self.get_cursor(dictionary=True)

        cursor.execute("SELECT id, username, create_time FROM users")
        users = cursor.fetchall()

        cursor.execute(
            """
            SELECT up.user, p.name
            FROM userpermissions up
                     JOIN permissions p ON up.permission = p.id
            """
        )
        permission_rows = cursor.fetchall()

        permissions_by_user = {}
        for row in permission_rows:
            permissions_by_user.setdefault(row["user"], []).append(row["name"])

        for user in users:
            user["permissions"] = permissions_by_user.get(user["id"], [])

        return users

    def delete_user(self, user_id: int):
        """Deletes a user and their associated permissions cascadingly."""
        cursor = self.get_cursor()
        cursor.execute("DELETE FROM userpermissions WHERE user = %s", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        self.commit()

    # endregion

    # region permissions
    def _resolve_child_permissions(self, direct_permission_names: list) -> list:
        """Helper to recursively find all child permissions implied by holding a parent permission."""
        all_perms = self.get_all_permissions()  # list of dicts with id, name, parent_id

        # Maps parent_id -> list of child dicts
        hierarchy_map = {}
        # Maps name -> id
        name_to_id = {}
        for p in all_perms:
            name_to_id[p['name']] = p['id']
            if p['parent_id'] is not None:
                hierarchy_map.setdefault(p['parent_id'], []).append(p)

        resolved_names = set(direct_permission_names)
        # Queue seeds from what the user explicitly holds
        queue = [name_to_id[name] for name in direct_permission_names if name in name_to_id]

        # BFS traversal down the tree
        while queue:
            current_parent_id = queue.pop(0)
            if current_parent_id in hierarchy_map:
                for child in hierarchy_map[current_parent_id]:
                    if child['name'] not in resolved_names:
                        resolved_names.add(child['name'])
                        queue.append(child['id'])

        return list(resolved_names)

    def get_all_permissions(self):
        """Fetches all permissions, including their parent_id relation."""
        cursor = self.get_cursor(dictionary=True)
        cursor.execute("SELECT id, name, parent_id FROM permissions")
        return cursor.fetchall()

    def get_all_available_permissions(self):
        """Alias or updated query for available permissions."""
        return self.get_all_permissions()

    def update_user_permissions(self, user_id: int, permission_ids):
        """Clears existing permissions and assigns a new list of permission IDs."""
        cursor = self.get_cursor()
        cursor.execute("DELETE FROM userpermissions WHERE user = %s", (user_id,))

        if permission_ids:
            insert_query = "INSERT INTO userpermissions (user, permission) VALUES (%s, %s)"
            permission_values = [(user_id, int(permission_id)) for permission_id in permission_ids]
            cursor.executemany(insert_query, permission_values)

        self.commit()

    def create_permission(self, permission_name: str, parent_id: int | None = None) -> bool:
        cursor = self.get_cursor()
        cursor.execute(
            "INSERT INTO permissions (name, parent_id) VALUES (%s, %s)",
            (permission_name, parent_id if parent_id else None),
        )
        self.commit()
        return cursor.rowcount > 0

    def delete_permission(self, permission_id: int) -> bool:
        cursor = self.get_cursor()
        cursor.execute("DELETE FROM permissions WHERE id = %s", (permission_id,))
        self.commit()
        return cursor.rowcount > 0

    def update_permission_hierarchy(self, permission_id: int, parent_id: int | None = None):
        """Updates the parent relationship of an existing permission."""
        cursor = self.get_cursor()
        cursor.execute(
            "UPDATE permissions SET parent_id = %s WHERE id = %s",
            (parent_id if parent_id else None, permission_id)
        )
        self.commit()

    def get_user_permissions(self, username: str):
        cursor = self.get_cursor(dictionary=True)
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            return None

        cursor.execute(
            """
            SELECT p.name
            FROM userpermissions up
                     JOIN permissions p ON up.permission = p.id
            WHERE up.user = %s
            """,
            (user["id"],),
        )
        direct_permissions = [row["name"] for row in cursor.fetchall()]

        # Dynamically compute inherited child permissions
        full_permissions = self._resolve_child_permissions(direct_permissions)

        return {
            "id": user["id"],
            "permissions": full_permissions,
        }
    # endregion
    #region Exams
    def get_all_exams(self):
        cursor = self.get_cursor(dictionary=True)
        cursor.execute("SELECT id, name, date, time, location, duration, capacity, status FROM exams")
        return cursor.fetchall()
    #endregion


# Maintain alias consistency mapping back to the lower-case export wrapper found in app.py
kaes_database = KaesDatabase