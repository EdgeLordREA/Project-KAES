import select
import socket
import threading
from sqlite3 import Cursor

from mysql.connector import pooling
import mysql.connector
import bcrypt
import paramiko

import SECRETS

# region pooling
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


# endregion

# noinspection PyBroadException
class KaesDatabase:
    # region boilerplate
    def __init__(self):
        if _connection_pool is None:
            raise RuntimeError("Database pool has not been initialized. Call initialize_global_tunnel() first.")
        # Seamlessly grab a completely clean, thread-isolated connection from the pool
        self.connection = _connection_pool.get_connection()

    def get_cursor(self, dictionary: bool = False) -> Cursor:
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

    # endregion

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
    def add_user(self, username: str, password: str, group_id: int | None = None):
        cursor = self.get_cursor()
        password_hash = self._hash_password(password)

        cursor.execute(
            "INSERT INTO users (username, password, `group`) VALUES (%s, %s, %s)",
            (username, password_hash, group_id),
        )
        self.commit()

    def get_all_users(self):
        """Fetches all users and their associated permissions and groups."""
        cursor = self.get_cursor(dictionary=True)

        cursor.execute("SELECT id, username, create_time, `group` FROM users")
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
            # Fetch group name if user has a group
            if user["group"]:
                cursor.execute("SELECT name FROM groups WHERE id = %s", (user["group"],))
                group_result = cursor.fetchone()
                user["group_name"] = group_result["name"] if group_result else None
            else:
                user["group_name"] = None

        return users

    def delete_user(self, user_id: int):
        """Deletes a user and their associated permissions cascadingly."""
        cursor = self.get_cursor()
        cursor.execute("UPDATE users SET deleted = %s WHERE id = %s", (1, user_id,))
        self.commit()

    def permanent_delete_user(self, user_id: int):
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
    # region Exams
    def get_all_exams(self):
        cursor = self.get_cursor(dictionary=True)
        cursor.execute("SELECT id, name, description FROM exams")
        return cursor.fetchall()

    def get_exam_by_id(self, exam_id):
        cursor = self.get_cursor()
        cursor.execute(
            """
            SELECT e.id          AS exam_id,
                   e.name        AS exam_name,
                   e.description AS exam_description,
                   q.id          AS question_id,
                   q.question    AS question_text,
                   q.category    AS question_category,
                   q.modifier    AS question_modifier,
                   c.name        AS category_name
            FROM exams e
                     LEFT JOIN examquestions eq ON e.id = eq.exam
                     LEFT JOIN questions q ON eq.question = q.id
                     LEFT JOIN categories c ON q.category = c.category_id
            WHERE e.id = %s
            """, (exam_id,)
        )
        rows = cursor.fetchall()

        if not rows:
            return None

        # Build the base exam info from the first row
        exam = {
            "id": rows[0]["exam_id"] if isinstance(rows[0], dict) else rows[0][0],
            "name": rows[0]["exam_name"] if isinstance(rows[0], dict) else rows[0][1],
            "description": rows[0]["exam_description"] if isinstance(rows[0], dict) else rows[0][2],
            "questions": []
        }

        # Populate the questions list if any exist
        for row in rows:
            # Handle both dictionary and tuple cursor factories safely
            q_id = row["question_id"] if isinstance(row, dict) else row[3]

            if q_id is not None:  # Ensure there is actually a question linked
                question_data = {
                    "id": q_id,
                    "text": row["question_text"] if isinstance(row, dict) else row[4],
                    "category_id": row["question_category"] if isinstance(row, dict) else row[5],
                    "modifier": row["question_modifier"] if isinstance(row, dict) else row[6],
                    "category_name": row["category_name"] if isinstance(row, dict) else row[7]
                }
                exam["questions"].append(question_data)

        return exam

    def create_exam(self, exam_name, exam_description):
        cursor = self.get_cursor()
        cursor.execute(
            """
            INSERT INTO exams (name, description)
            VALUES (%s, %s)
            """,
            (exam_name, exam_description),
        )
        self.commit()

    def delete_exam(self, exam_id: int):
        cursor = self.get_cursor()
        cursor.execute(
            """
            UPDATE exams SET deleted = %s WHERE id = %s
            """,
            (1, exam_id),
        )
        self.commit()

    def permanent_delete_exam(self, exam_id: int):
        cursor = self.get_cursor()
        cursor.execute(
            """
            DELETE FROM exams WHERE id = %s
            """,
            (exam_id,),
        )
        self.commit()

    def add_question_to_exam(self, exam_id: int, question_id: int):
        """Links an existing question ID to an exam ID in the junction table."""
        cursor = self.get_cursor()
        cursor.execute(
            """
            INSERT INTO examquestions (exam, question)
            VALUES (%s, %s)
            """,
            (exam_id, question_id),
        )
        self.commit()

    def create_question(self, question, category, modifier):
        cursor = self.get_cursor()
        cursor.execute(
            """
            INSERT INTO questions (question, category, modifier)
            VALUES (%s, %s, %s)
            """,
            (question, category, modifier),
        )
        self.commit()
        return cursor.lastrowid

    def edit_question(self, questionid, question, category, modifier):
        cursor = self.get_cursor()
        cursor.execute(
            """
            UPDATE questions
            SET question = %s,
                category = %s,
                modifier = %s
            WHERE id = %s
            """,
            (question, category, modifier, questionid),
        )
        self.commit()

    def delete_question(self, questionid):
        cursor = self.get_cursor()
        cursor.execute(
            """
            UPDATE questions SET deleted = %s WHERE id = %s
            """,
            (1, questionid),
        )
        self.commit()

    def permanent_delete_question(self, questionid):
        cursor = self.get_cursor()
        cursor.execute(
            """
            DELETE FROM questions WHERE id = %s
            """,
            (questionid,),
        )
        self.commit()

    def create_category(self, categoryname):
        cursor = self.get_cursor()
        cursor.execute(
            """
            INSERT INTO categories (name)
            VALUES (%s)
            """,
            (categoryname,),
        )
        self.commit()
        return cursor.lastrowid

    def get_all_categories(self):
        cursor = self.get_cursor(dictionary=True)
        cursor.execute("SELECT category_id, name FROM categories")
        categories = cursor.fetchall()
        return categories
    # endregion

    # region Groups
    def get_all_groups(self):
        """Fetches all groups."""
        cursor = self.get_cursor(dictionary=True)
        cursor.execute("SELECT id, name FROM groups")
        return cursor.fetchall()

    def create_group(self, group_name: str) -> bool:
        """Creates a new group."""
        cursor = self.get_cursor()
        cursor.execute(
            "INSERT INTO groups (name) VALUES (%s)",
            (group_name,)
        )
        self.commit()
        return cursor.rowcount > 0

    def update_group(self, group_id: int, group_name: str) -> bool:
        """Updates an existing group."""
        cursor = self.get_cursor()
        cursor.execute(
            "UPDATE groups SET name = %s WHERE id = %s",
            (group_name, group_id)
        )
        self.commit()
        return cursor.rowcount > 0

    def delete_group(self, group_id: int) -> bool:
        """Deletes a group (sets users to NULL group)."""
        cursor = self.get_cursor()
        # First, unset the group for all users in this group
        cursor.execute(
            "UPDATE users SET `group` = NULL WHERE `group` = %s",
            (group_id,)
        )
        # Then delete the group
        cursor.execute("DELETE FROM groups WHERE id = %s", (group_id,))
        self.commit()
        return cursor.rowcount > 0

    def get_users_by_group(self, group_id: int):
        """Fetches all users in a specific group."""
        cursor = self.get_cursor(dictionary=True)
        cursor.execute(
            "SELECT id, username, create_time FROM users WHERE `group` = %s AND deleted = 0",
            (group_id,)
        )
        return cursor.fetchall()

    def update_user_group(self, user_id: int, group_id: int | None) -> bool:
        """Updates a user's group assignment."""
        cursor = self.get_cursor()
        cursor.execute(
            "UPDATE users SET `group` = %s WHERE id = %s",
            (group_id, user_id)
        )
        self.commit()
        return cursor.rowcount > 0
    # endregion


# Maintain alias consistency mapping back to the lower-case export wrapper found in app.py
kaes_database = KaesDatabase
