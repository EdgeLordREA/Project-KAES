import select
import socket
import threading

import bcrypt
import mysql.connector
import paramiko

import SECRETS


# noinspection PyBroadException
class kaes_database:

    # region Boilerplate
    def __init__(self):
        # SSH Settings
        self.ssh_host = SECRETS.SSH_HOST
        self.ssh_user = SECRETS.SSH_USER
        self.ssh_password = SECRETS.SSH_PASSWORD

        # MySQL Settings
        self.db_host = SECRETS.SB_HOST
        self.db_user = SECRETS.DB_USERNAME
        self.db_password = SECRETS.DB_PASSWORD
        self.db_port = SECRETS.DB_PORT

        self.ssh_client = None
        self.transport = None
        self.local_bind_port = None
        self.server_socket = None
        self.forwarding_thread = None
        self.connection = None
        self._connect()

    def _connect(self):
        try:
            # 1. Create an SSH client and connect
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(
                hostname=self.ssh_host,
                port=22,
                username=self.ssh_user,
                password=self.ssh_password
            )

            # 2. Open a transport and start a local port forward
            self.transport = self.ssh_client.get_transport()

            # Find an available local port
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('127.0.0.1', 0))
            self.server_socket.listen(5)
            self.local_bind_port = self.server_socket.getsockname()[1]

            # Start the forwarding thread
            self.forwarding_thread = threading.Thread(
                target=self._forward_tunnel,
                daemon=True
            )
            self.forwarding_thread.start()

            # 3. Connect to MySQL via the local forwarded port
            self.connection = mysql.connector.connect(
                host='127.0.0.1',
                port=self.local_bind_port,
                user=self.db_user,
                password=self.db_password,
                database='nbuch'
            )

            if self.connection.is_connected():
                print(f"Successfully connected to Database via SSH tunnel on local port {self.local_bind_port}")

        except Exception as e:
            print(f"Error connecting: {e}")
            self.close()
            raise

    def _forward_tunnel(self):
        """Thread that handles forwarding traffic between local port and remote MySQL."""
        if not self.server_socket or not self.transport:
            return
        chan = None
        sock = None
        try:
            while True:
                # Accept local connections
                sock, addr = self.server_socket.accept()

                # Open a channel to the remote MySQL host
                chan = self.transport.open_channel(
                    'direct-tcpip',
                    (self.db_host, self.db_port),
                    addr
                )

                if chan is None:
                    sock.close()
                    continue

                # Bidirectional forwarding
                while True:
                    r, w, x = select.select([sock, chan], [], [])
                    if sock in r:
                        data = sock.recv(1024)
                        if len(data) == 0:
                            break
                        chan.send(data)
                    if chan in r:
                        data = chan.recv(1024)
                        if len(data) == 0:
                            break
                        sock.send(data)

                chan.close()
                sock.close()

        except Exception:
            pass
        finally:
            if chan:
                chan.close()
            if sock:
                sock.close()

    def close(self):
        """Close the connection and stop the tunnel."""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("MySQL connection closed")

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            print("Local tunnel socket closed")

        if self.transport:
            try:
                self.transport.close()
            except Exception:
                pass
            print("SSH transport closed")

        if self.ssh_client:
            try:
                self.ssh_client.close()
            except Exception:
                pass
            print("SSH client closed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def commit(self):
        """
        Commit any pending transaction to the database.
        """
        if not self.connection:
            raise RuntimeError("Database connection is not established.")

        self.connection.commit()

    # endregion

    def get_cursor(self, dictionary=False):
        """
        Helper method to quickly grab a cursor.
        Setting dictionary=True returns rows as dicts instead of tuples.
        """
        if not self.connection:
            raise RuntimeError("Database connection is not established.")

        return self.connection.cursor(dictionary=dictionary)

    def login(self, username, password):
        # 1. Use context manager ('with') so the cursor auto-closes when done
        with self.get_cursor(dictionary=True) as cursor:
            query = "SELECT password FROM users WHERE username = %s"

            # Note: Arguments must be passed as a tuple/list: (username,
            cursor.execute(query, (username,))
            user = cursor.fetchone()

            # If user doesn't exist
            if not user:
                return False

            return bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8'))

    def add_user(self, username, password):
        with self.get_cursor() as cursor:
            query = "INSERT INTO users (username, password) VALUES (%s, %s)"

            # Generate hash and decode to string so it stores nicely in a VARCHAR field
            hashpass = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            cursor.execute(query, (username, hashpass))
            self.commit()

    def get_user_permissions(self, username):
        """
        Fetches the user's ID and an array of their assigned permission names
        matching the 'users', 'userpermissions', and 'permissions' schema.
        """
        with self.get_cursor(dictionary=True) as cursor:
            # First, verify the user exists and grab their ID
            user_query = "SELECT id FROM users WHERE username = %s"
            cursor.execute(user_query, (username,))
            user = cursor.fetchone()

            if not user:
                return None  # User doesn't exist or was deleted

            # Next, grab all permission strings linked to this user's ID
            perm_query = """
                SELECT p.name 
                FROM userpermissions up
                JOIN permissions p ON up.permission = p.id
                WHERE up.user = %s
            """
            cursor.execute(perm_query, (user['id'],))
            rows = cursor.fetchall()

            # Extract permission names into a clean list: ['admin', 'student'], etc.
            permissions_list = [row['name'] for row in rows]

            return {
                'id': user['id'],
                'permissions': permissions_list
            }

    def get_all_users(self):
        """Fetches all users and their associated permissions."""
        with self.get_cursor(dictionary=True) as cursor:
            # Fetch all users
            cursor.execute("SELECT id, username, create_time FROM users")
            users = cursor.fetchall()

            # Fetch all permission assignments
            query = """
                    SELECT up.user, p.name
                    FROM userpermissions up
                             JOIN permissions p ON up.permission = p.id \
                    """
            cursor.execute(query)
            permission_rows = cursor.fetchall()

            # Group permissions by user ID
            user_perms = {}
            for row in permission_rows:
                user_perms.setdefault(row['user'], []).append(row['name'])

            # Combine them
            for user in users:
                user['permissions'] = user_perms.get(user['id'], [])

            return users

    def get_all_available_permissions(self):
        """Fetches all possible permission types from the permissions table."""
        with self.get_cursor(dictionary=True) as cursor:
            cursor.execute("SELECT id, name FROM permissions")
            return cursor.fetchall()

    def delete_user(self, user_id):
        """Deletes a user and their associated permissions cascadingly."""
        with self.get_cursor() as cursor:
            # First, clean up the join table for this user
            cursor.execute("DELETE FROM userpermissions WHERE user = %s", (user_id,))
            # Delete it from the users table
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            self.commit()

    def update_user_permissions(self, user_id, permission_ids):
        """Clears existing permissions and assigns a new list of permission IDs."""
        with self.get_cursor() as cursor:
            # Remove old permissions
            cursor.execute("DELETE FROM userpermissions WHERE user = %s", (user_id,))

            # Insert new permissions
            if permission_ids:
                insert_query = "INSERT INTO userpermissions (user, permission) VALUES (%s, %s)"
                # Prepare data tuple list for executemany
                data = [(user_id, int(perm_id)) for perm_id in permission_ids]
                cursor.executemany(insert_query, data)

            self.commit()