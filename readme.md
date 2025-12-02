###Manual start
```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt 
python3 app.py
```
---
###Start as linux service

Create file:
`/etc/systemd/system/mlingvo.service 

```
[Unit]
Description=My Python Script Service
After=network.target

[Service]
Type=simple
#User=ваш_пользователь
WorkingDirectory=/opt/mlingvo
ExecStart=/opt/mlingvo/.venv/bin/python /opt/mlingvo/app.py
Restart=always

[Install]
WantedBy=multi-user.target
```
```
sudo systemctl daemon-reload
systemctl enable  mlingvo.service
systemctl start mlingvo.service
```