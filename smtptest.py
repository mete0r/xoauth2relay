from email.mime.text import MIMEText
import smtplib
import sys


def main():
    sender = to = sys.argv[1]
    subject = sys.argv[2]
    msg = MIMEText(sys.argv[3])

    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = to

    s = smtplib.SMTP('localhost', 2500)
    s.sendmail(sender, [to], msg.as_string())
    s.quit()


if __name__ == '__main__':
    main()
