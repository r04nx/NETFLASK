from flask import Flask, jsonify, redirect, render_template, request, session, url_for
import subprocess
import socket
import nmap
import requests
import dns.resolver
import re
import matplotlib
import os
matplotlib.use('Agg')
from matplotlib import pyplot as plt


app = Flask(__name__)
app.debug = True
app.secret_key = 'mysecretkey'



def check_port(ip_address, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip_address, port))
    if result == 0:
        nm = nmap.PortScanner()
        nm.scan(ip_address, str(port))
        service = nm[ip_address]['tcp'][port]['name']
        status = nm[ip_address]['tcp'][port]['state']
        version = nm[ip_address]['tcp'][port]['version']
        return {'port': port, 'service': service, 'status': status, 'version': version}



def ping_test(hostname):
    result = subprocess.run(['ping','-n','10', hostname], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode('utf-8').replace('\n', '<br>')
    return output


def traceroute(hostname):
    result = subprocess.run(['tracert', hostname], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode('utf-8').replace('\n', '<br>').replace('  ', '&nbsp&nbsp&nbsp')
    return output


def dnslook(hostname):
    results = socket.getaddrinfo(hostname, None)

    resolver = dns.resolver.Resolver()

    dns_info = {}
    for result in results:
        family, socktype, proto, canonname, sockaddr = result
        ip_address = sockaddr[0]
        dns_info['IP Address'] = ip_address

        try:
            answers = resolver.query(hostname, 'MX')
            mx_records = [str(rdata.exchange) for rdata in answers]
            dns_info['MX Records'] = mx_records
        except:
            pass

        try:
            answers = resolver.query(hostname, 'CNAME')
            cname = str(answers[0])
            dns_info['cname'] = cname
        except:
            pass

        return dns_info
















@app.route('/auth', methods=['POST'])
def auth():
    title = 'Login'
    username = request.form['username']
    password = request.form['password']

    if(username=='nargis' and password=='1234'):
        session['username'] = username
        session['logged_in'] = True
        session['user_role'] = username
        return render_template('nav.html')
    else:
        return render_template('login.html', error='Wrong username/password, try again.')




@app.route('/')
def login():
    # if(not session['logged_in']):
    #     title = 'Login'
        return render_template('login.html')
    # else:
    #     return render_template('nav.html')

@app.route('/ping')
def ping():
    if(session['logged_in']):
        title = 'Ping'
        return render_template('ping.html')
    else:
        return redirect(url_for('login'))
    
@app.route('/pingtest', methods=['POST'])
def pingtest():
    title = 'Ping Test'
    hostname = request.form['input']
    output=ping_test(hostname)
    ping_times = re.findall('time=(\d+\.?\d*)', output)

    # Convert ping times to floats
    ping_times = [float(t) for t in ping_times]

    # Plot the ping times
    plt.plot(ping_times)
    plt.title('Ping Times')
    plt.xlabel('Ping Number')
    plt.ylabel('Ping Time (ms)')
    plt.savefig('./static/ping_plot.png')
    src="../static/ping_plot.png"
    return render_template('ping.html', output=output, src=src )

@app.route('/delete', methods=['POST'])
def delete_image():
    filename = request.form['filename']
    if os.path.exists(filename):
        os.remove(filename)
        return 'Image deleted successfully'
    else:
        return 'Image not found'

    
    



@app.route('/ports')
def ports():
    if(session['logged_in']):
        title = 'Port Scanner'
        return render_template('ports.html')    

@app.route('/portscanner', methods=['POST'])
def portscanner():
    if(session['logged_in']):
        hostname = request.form['input']
        ip_address = hostname
        portdict = []
        ports = [80, 443, 20, 21, 22, 23, 25, 53, 67, 68]
        for port in ports:
            result = check_port(ip_address, port)
            if result:
                portdict.append(result)
        title = 'Port Scanner'
        return render_template('ports.html', portdict=portdict)
    else:
        return redirect(url_for('login'))

@app.route('/ipconfig')
def ipconfig():
    if(session['logged_in']):
        ip_address = request.args.get('ip')
        url = f'https://ipinfo.io/{ip_address}?token=8883a92a738fb3'
        response = requests.get(url)
        output = response.json()
        print(output)
        return render_template('ipconfig.html', output=output)
    else:
        return redirect(url_for('login'))
    


@app.route('/tracert')
def tracert():
    if(session['logged_in']):
        title = 'tracert'
        return render_template('tracert.html')
    else:
        return redirect(url_for('login'))

@app.route('/traceroute',methods=['POST'])
def trace_route():
    if(session['logged_in']):
        hostname = request.form['input']
        output=traceroute(hostname)
        return render_template('tracert.html', output=output)
    else:
        return redirect(url_for('login'))


@app.route('/dnslookup', methods=['GET'])
def dnslookup():
    if(request.args.get('input')):
        hostname=request.args.get('input')
        result = dnslook(hostname)
        print(result)
        return render_template('dnslookup.html', result=result)
    else:
        return(render_template('dnslookup.html'))

@app.route('/logout')
def logout():
    session['logged_in'] = False
    return redirect(url_for('login'))



if __name__ == '__main__':
    app.run()
   
