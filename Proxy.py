# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re
import traceback


# 1MB buffer size
BUFFER_SIZE = 1000000

#function to sanitize filenames with special characters
def sanitize_filename(url):
    return re.sub(r'[<>:"/\\|?*]', '_', url)


# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening
try:
  # Create a server socket
  # ~~~~ INSERT CODE ~~~~
  server_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM) # note TCP uses SOCK_STREAM and UDP uses SOCK_DGRAM
  # ~~~~ END CODE INSERT ~~~~
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # Bind the the server socket to a host and port
  # ~~~~ INSERT CODE ~~~~
  server_socket.bind((proxyHost, proxyPort))
  # ~~~~ END CODE INSERT ~~~~
  print ('Port is bound')
except:
  print('Port is already in use')
  sys.exit()

try:
  # Listen on the server socket
  # ~~~~ INSERT CODE ~~~~
  server_socket.listen(1)
  # ~~~~ END CODE INSERT ~~~~
  print ('Listening to socket')
except:
  print ('Failed to listen')
  sys.exit()

# continuously accept connections
while True:
  print ('Waiting for connection...')
  clientSocket = None

  # Accept connection from client and store in the clientSocket
  try:
    # ~~~~ INSERT CODE ~~~~
    clientSocket, client_address = server_socket.accept()
    # ~~~~ END CODE INSERT ~~~~
    print ('Received a connection')
  except:
    print ('Failed to accept connection')
    sys.exit()

  # Get HTTP request from client
  # and store it in the variable: message_bytes
  # ~~~~ INSERT CODE ~~~~
  message_bytes = clientSocket.recv(BUFFER_SIZE)
  # ~~~~ END CODE INSERT ~~~~
  message = message_bytes.decode('utf-8')
  print ('Received request:')
  for line in message.split('\r\n'):
    print('< ' + line)

  lines = message.split('\r\n')

  request_line = lines[0]  # First line is the request line
  print(f"Request Line: {request_line}")

  method, URI, version = request_line.split(' ', 2)

  print ('Method:\t\t' + method)
  print ('URI:\t\t' + URI)
  print ('Version:\t' + version)
  print ('')

  # Get the requested resource from URI
  # Remove http protocol from the URI
  URI = re.sub('^(/?)http(s?)://', '', URI, count=1)

  # Remove parent directory changes - security
  URI = URI.replace('/..', '')

  # Split hostname from resource name
  resourceParts = URI.split('/', 1)
  hostname = resourceParts[0]
  resource = '/'

  if len(resourceParts) == 2:
    # Resource is absolute URI with hostname and resource
    resource = resource + resourceParts[1]

  print ('Requested Resource:\t' + resource)

  


  # Check if resource is in cache
  try:
    cacheLocation = './' + hostname + '/' + sanitize_filename(resource)
    if cacheLocation.endswith('/'): 
        cacheLocation += 'default'

    os.makedirs(os.path.dirname(cacheLocation), exist_ok=True)   

    # Check wether the file is currently in the cache
    with open(cacheLocation, "r") as cacheFile:
      cacheData = cacheFile.readlines()
    print ('Cache hit! Loading from cache file: ' + cacheLocation)
    cacheData="".join(cacheData)
    
    # ProxyServer finds a cache hit
    # Send back response to client 
    # ~~~~ INSERT CODE ~~~~
    clientSocket.sendall(cacheData.encode())

    # ~~~~ END CODE INSERT ~~~~
    print ('Sent to the client:')
    print ('> ' + cacheData)
  except:
    # cache miss.  Get resource from origin server
    originServerSocket = None
    # Create a socket to connect to origin server
    # and store in originServerSocket
    # ~~~~ INSERT CODE ~~~~
    originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Created new socket for origin server")
  # ~~~~ END CODE INSERT ~~~~

    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      address = socket.gethostbyname(hostname)
      # Connect to the origin server
      # ~~~~ INSERT CODE ~~~~
      originServerSocket.connect((address, 80))
      # ~~~~ END CODE INSERT ~~~~
      print ('Connected to origin Server')

      originServerRequest = ''
      
    
      # Create origin server request line and headers to send
      # and store in originServerRequestHeader and originServerRequest
      # originServerRequest is the first line in the request and
      # originServerRequestHeader is the second line in the request
      # ~~~~ INSERT CODE ~~~~
      originServerRequestHeader = method + ' ' + resource + ' ' + version
      headers = message.splitlines()[1:]
    
      for i, item in enumerate(headers):
        if item.startswith("Host:"):
          headers[i] = "Host: " + hostname + ":" + "80"
   
      # ~~~~ END CODE INSERT ~~~~
      
      # Construct the request to send to the origin server
      request = originServerRequestHeader + '\r\n' + '\r\n'.join(headers) + '\r\n\r\n'

      #print("Constructed request to origin server:")
      #print(request)      

      # Request the web resource from origin server
      print ('Forwarding request to origin server:')
      for line in request.split('\r\n'):
        print ('> ' + line)

      try:
        originServerSocket.sendall(request.encode())
      except socket.error:
        print ('Forward request to origin failed')
        sys.exit()

      print('Request sent to origin server\n')

      # Get the response from the origin server
      # ~~~~ INSERT CODE ~~~~
      originServerResponse = originServerSocket.recv(BUFFER_SIZE).decode('utf-8')
      headers, body = originServerResponse.split('\r\n\r\n', 1)
      
      status_code = int(headers.split(' ')[1])
      #print(status_code)

      # Check for Cache-Control header
      cache_control = None

      for header in headers.split('\r\n'):
          if header.lower().startswith('cache-control:'):
            cache_control = header
            break

      if status_code in [200, 301]:
        if not cache_control:
        # Add Cache-Control header if not present
          cache_control = 'Cache-Control: public, max-age=3600'  # 1-hour caching
          headers += '\r\n' + cache_control


      originServerResponse = headers + '\r\n\r\n' + body

      if status_code in [200, 301]:
        try:
          with open(cacheLocation, 'wb') as cacheFile:
            cacheFile.write(originServerResponse.encode())
          print(f'Cached response for status {status_code}')
        except Exception as e:
          print(f'Error caching file: {e}')

      max_age = None
      if cache_control:
        for directive in cache_control.split(','):
            if 'max-age' in directive:
                max_age = int(directive.split('=')[1].strip())
                break
      
      # Cache the response based on max-age if it exists
      if max_age is not None:
          with open(cacheLocation, 'wb') as cacheFile:
            cacheFile.write(body.encode('utf-8'))
          print(f'Cached response for {max_age} seconds.')

            # Send the response to the client
        # ~~~~ INSERT CODE ~~~~
      clientSocket.sendall(originServerResponse.encode())
        # ~~~~ END CODE INSERT ~~~~

      with open(cacheLocation, 'wb') as cacheFile:

        # Save origin server response in the cache file
        # ~~~~ INSERT CODE ~~~~
        cacheFile.write(originServerResponse.encode())
        # ~~~~ END CODE INSERT ~~~~
      print ('cache file closed')

        # finished communicating with origin server - shutdown socket writes
      print ('origin response received. Closing sockets')
      originServerSocket.close()
        
      clientSocket.shutdown(socket.SHUT_WR)
      print ('client socket shutdown for writing')

            # ~~~~ END CODE INSERT ~~~~
    except OSError as err:
      print ('Cache Failed. ' + err.strerror)

    try:
      clientSocket.close()
    except:
      print ('Failed to close client socket')
