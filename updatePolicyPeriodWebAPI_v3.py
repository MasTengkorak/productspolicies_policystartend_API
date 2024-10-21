from flask import Flask, jsonify, request
import paramiko
import pymysql
from sshtunnel import SSHTunnelForwarder
import os
from dotenv import load_dotenv

app = Flask(__name__)

# Load environment variables from .env file
load_dotenv()

# Configuration for SSH
SSH_HOST = os.getenv("SSH_HOST")
SSH_PORT = int(os.getenv("SSH_PORT"))

# Configuration for MySQL
MYSQL_HOST = os.getenv("MYSQL_HOST")
MYSQL_PORT = int(os.getenv("MYSQL_PORT"))
MYSQL_USER = os.getenv("MYSQL_USER")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_DB = os.getenv("MYSQL_DB")

def create_ssh_tunnel_and_connect(cert_location, ssh_user, ssh_password):
    # Create a Paramiko RSAKey object with passphrase
    mykey = paramiko.Ed25519Key.from_private_key_file(cert_location, password=ssh_password)
        
    # Establishing SSH Tunnel and MySQL Connection
    tunnel = SSHTunnelForwarder(
        (SSH_HOST, SSH_PORT),                # SSH address
        ssh_username=ssh_user,               # SSH username
        ssh_pkey=mykey,                      # Pass the RSAKey object that includes the passphrase
        remote_bind_address=(MYSQL_HOST, MYSQL_PORT)  # MySQL server address behind SSH
    )
    tunnel.start()
        
    connection = pymysql.connect(
        host='127.0.0.1',                # This is the local endpoint of the SSH tunnel
        port=tunnel.local_bind_port,     # The local port to which the tunnel forwards MySQL
        user=MYSQL_USER,                 # MySQL database username
        password=MYSQL_PASSWORD,         # MySQL password
        db=MYSQL_DB                      # Database name
    )
        
    return tunnel, connection

# Usage of the function
@app.route('/p_policies', methods=['GET'])
def get_policies():
    cert_location = request.headers.get('X-Cert-Location')
    ssh_user = request.headers.get('X-SSH-User')
    ssh_password = request.headers.get('X-SSH-Password')
    
    if not cert_location or not ssh_user or not ssh_password:
        return jsonify({"error": "Certificate location, SSH user, and SSH password are required"}), 400

    connection, conn = create_ssh_tunnel_and_connect(cert_location, ssh_user, ssh_password)
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT * FROM products_policies ORDER BY id DESC LIMIT 10;")
            result = cursor.fetchall()
            return jsonify(result)
    finally:
        conn.close()
        connection.stop()

@app.route('/gp_policies/<policy_id>', methods=['GET'])
def get_policy_by_number(policy_id):
    cert_location = request.headers.get('X-Cert-Location')
    ssh_user = request.headers.get('X-SSH-User')
    ssh_password = request.headers.get('X-SSH-Password')
    
    if not cert_location or not ssh_user or not ssh_password:
        return jsonify({"error": "Certificate location, SSH user, and SSH password are required"}), 400

    connection, conn = create_ssh_tunnel_and_connect(cert_location, ssh_user, ssh_password)
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT * FROM products_policies WHERE policy_id = %s;", (policy_id,))
            result = cursor.fetchone()
            if result:
                return jsonify(result)
            else:
                return jsonify({"error": "Policy not found"}), 404
    finally:
        conn.close()
        connection.stop()
        
@app.route('/up_policies/<policy_id>', methods=['PUT'])
def update_policy_dates(policy_id):
    cert_location = request.headers.get('X-Cert-Location')
    ssh_user = request.headers.get('X-SSH-User')
    ssh_password = request.headers.get('X-SSH-Password')
    
    if not cert_location or not ssh_user or not ssh_password:
        return jsonify({"error": "Certificate location, SSH user, and SSH password are required"}), 400

    data = request.get_json()
    policy_start = data.get('policy_start')
    policy_end = data.get('policy_end')

    if not policy_start or not policy_end:
        return jsonify({"error": "policy_start and policy_end are required"}), 400

    connection, conn = create_ssh_tunnel_and_connect(cert_location, ssh_user, ssh_password)
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE products_policies SET policy_start = %s, policy_end = %s WHERE policy_id = %s;",
                (policy_start, policy_end, policy_id)
            )
            conn.commit()
            if cursor.rowcount > 0:
                return jsonify({"message": "Policy dates updated successfully"})
            else:
                return jsonify({"error": "Policy not found"}), 404
    finally:
        conn.close()
        connection.stop()

if __name__ == '__main__':
    app.run(debug=True, port=9070, host='0.0.0.0')