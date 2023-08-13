FROM python:3.9-alpine

WORKDIR /walletwatch

COPY . /walletwatch

RUN pip install --no-cache-dir -r requirements.txt
RUN pip install python-dotenv

EXPOSE 5000 3306

ENV FLASK_APP=walletwatch.py
ENV FLASK_ENV=development

CMD ["flask", "run", "--host=0.0.0.0"]