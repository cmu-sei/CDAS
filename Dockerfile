FROM python:3.7
COPY . /app
WORKDIR /app
RUN mkdir cdas-output
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
CMD python3 -m cdas --overwrite-output --overwrite-temp
