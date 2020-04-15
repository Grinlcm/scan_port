# scan_port
> 分别使用python3调用nmap、masscan批量扫描IP多个端口,并对扫描后的端口进行访问检测,也就是形成IP+PORT+PATH的多重扫描检测
>
>运行指令:
>
>   python3 nmap_scan.py -i 127.0.0.1 -p 80 -path url_path.txt -outport outport.txt -outurl outurl.txt -t 10
>
>   python3 masscan_scan.py -i 127.0.0.1 -p 80 -path url_path.txt  -r 1000 -outport outport.txt -outurl outurl.txt -t 10

## 2020.4.15: 在检测url时使用多线程
