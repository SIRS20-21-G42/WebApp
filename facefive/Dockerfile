FROM python:3.7

## FOR DEBUG
# RUN apt install -yqq curl

# Flask listens by default on port 5000
EXPOSE 5000

WORKDIR /facefive

COPY requirements.txt /facefive
RUN pip3 install -r requirements.txt

COPY ./app/ /facefive
RUN cat /facefive/auth/CA.cert >> /usr/local/lib/python3.7/site-packages/certifi/cacert.pem

CMD python3 __init__.py