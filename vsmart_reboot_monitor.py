import paramiko
import time
import re
import logging
# logging.basicConfig(level=logging.DEBUG)

VSMART_IPS = ["192.168.1.21", "192.168.1.22"]
VSMART_USER = "admin"
VSMART_PASS = "admin"
# Number of seconds to wait between cycles of checking all VSMART_IPS
WAIT_BETWEEN_CHECKS = 300
REBOOT_CASE = "too many reboots"

MAX_BUFFER = 65535

def main(IP):
    status = "System state for vSmart IP {} not found".format(IP)
    ssh=paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(IP, port=22, username=VSMART_USER,
                                password=VSMART_PASS,
                                look_for_keys=False, allow_agent=False)

        remote_conn = ssh.invoke_shell()
        out = get_response(remote_conn)

        # disable --More-- paging
        send_command(remote_conn, "screen-length 0\n")

        send_command(remote_conn, "show system status\n")
        out = get_response(remote_conn)

        for line in out.split("\n"):
            if line.startswith("System state:"):
                status = line
                if REBOOT_CASE in line:
                    send_command(remote_conn, "reboot\n")
                    send_command(remote_conn, "yes\n")
                    return (True, status)
                return (False, status)

    except paramiko.AuthenticationException:
        print("Incorrect password:")

    except Exception as exception:
        print(str(exception))

    return (False, status)

def send_command(conn, data):
    conn.send(data)
    time.sleep(.4)

def get_response(conn):
    not_done = True
    max_loops = 25
    i = 0
    output = ""
    while not_done and (i <= max_loops):
        time.sleep(0.4)
        i += 1
        # Keep reading data as long as available (up to max_loops)
        if conn.recv_ready():
            last = clean_output(conn.recv(MAX_BUFFER).decode('ascii'))
            # print("last: {}".format(last[-21:-1]))
            output += last
        else:
            not_done = False
    return output


def clean_output(data):
    return data
    # data = str(data)
    # data = data.replace("\\r\\n", "\n")[2:-4]
    # return data

def strip_ansii_esc(string):
    # https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', string)

if __name__ == "__main__":
    print("!!Be sure to connect to all vSmart IP addresses via SSH before running this script!!")
    print("This is in order to add the SSH key to your known hosts")
    print()
    print("I'm running 'show system status' and looking at the 'System State'")
    print("The normal output is:")
    print("    System state:            GREEN. All daemons up")
    print("The failed state output is:  ")
    print("    System state: RED. Reboot (reason: Daemon 'ompd' failed) aborted.. too many reboots (7 reboots in last 24 hrs)")
    print()
    print("Once I see a vSmart in the failed state, I will reboot that vSmart")
    print("I will stop checking other vSmarts for failure until the cycle starts over")
    print()

    while(True):
        for ip in VSMART_IPS:
            print("Checking vSmart with IP address:  {}".format(ip))
            (rebooting_vsmart, status) = main(ip)
            print("    {}".format(status))
            if rebooting_vsmart:
                print("    !!Rebooting this vSmart!!".format(status))
                break
        print()
        print("Waiting {} seconds until next check...".format(WAIT_BETWEEN_CHECKS))
        print()
        time.sleep(WAIT_BETWEEN_CHECKS)
