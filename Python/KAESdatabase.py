import mysql.connector
from sshtunnel import SSHTunnelForwarder

class kaes_database:
    def __init__(self):
        # SSH Settings (from screenshot)
        self.ssh_host = 'eindhoven.rea.4u2c.nl'
        self.ssh_user = 'nbuch'
        # Note: You should use a key file or a secure way to handle passwords
        self.ssh_password = 'YOUR_SSH_PASSWORD'

        # MySQL Settings (from screenshot)
        self.db_host = '127.0.0.1'
        self.db_user = 'nbuch'
        self.db_password = 'YOUR_MYSQL_PASSWORD'
        self.db_name = 'kaes_db'
        self.db_port = 3306

        self.tunnel = None
        self.connection = None
        self._connect()

    def _connect(self):
        try:
            # 1. Start the SSH Tunnel
            self.tunnel = SSHTunnelForwarder(
                (self.ssh_host, 22),
                ssh_username=self.ssh_user,
                ssh_password=self.ssh_password,
                remote_bind_address=(self.db_host, self.db_port)
            )
            self.tunnel.start()

            # 2. Connect to MySQL via the tunnel's local port
            self.connection = mysql.connector.connect(
                host='127.0.0.1',
                port=self.tunnel.local_bind_port,
                user=self.db_user,
                password=self.db_password,
                database=self.db_name
            )

            if self.connection.is_connected():
                print(f"Successfully connected to {self.db_name} via SSH tunnel")

        except Exception as e:
            print(f"Error connecting: {e}")
            self.close()

    def close(self):
        """Close connection and stop the tunnel."""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("MySQL connection closed")
        if self.tunnel:
            self.tunnel.stop()
            print("SSH tunnel closed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()