## CaptureHoney

`CaptureHoney` is a Python script designed to capture and log connections, sending a custom message while offering no service to unwanted visitors. It operates as a Honeypot.

What is Honeypot? Click [here](https://en.wikipedia.org/wiki/Honeypot_(computing)) to know more.

![Honeypot_diagram](https://upload.wikimedia.org/wikipedia/commons/7/76/Honeypot_diagram.jpg)

### Requirements
- Python 3.x
- Unix-like operating system (tested on Ubuntu 20.04)

### Usage

1. Clone the repository:

```git clone https://github.com/ChrishSec/CaptureHoney.git```

2. Install the required dependencies:

```pip3 install -r requirements.txt```

3. Run the script:

```python3 CaptureHoney.py -ip 0.0.0.0 -p 8080```

By default, the script captures connections on IP address 0.0.0.0 and port 80. You can customize the IP and port by modifying the relevant arguments in the command.

### Screenshots

Coming Soon

![Screenshot 1](screenshots/screenshot_1.png)
![Screenshot 2](screenshots/screenshot_2.png)
![Screenshot 3](screenshots/screenshot_3.png)

## Disclaimer

This script is intended for educational and research purposes only. Use it at your own risk. The author is not responsible for any damage caused by the use or misuse of this script.

## License

This script is released under the GNU General Public License v3.0. Everyone is permitted to copy and distribute verbatim copies of this license document, but changing it is not allowed.

## Author

This script was developed by [ChrishSec](https://github.com/ChrishSec). Feel free to fork, modify, and distribute it. If you have any questions or suggestions, please reach out to the author on [Telegram](https://t.me/ChrishSec).
