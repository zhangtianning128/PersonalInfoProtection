# Dockerfile for app2

# 使用官方的 Python 基础镜像
FROM python:3.7

# 设置工作目录
WORKDIR /app

#ENV PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/

# 安装依赖
RUN pip install cryptography psycopg2

#RUN pip install flask qrcode[pil] pillow

WORKDIR /app

# 复制代码和密钥文件到容器中
COPY api.py public_key.pem private_key.pem /app/
#COPY . /app/

RUN ls /app

WORKDIR /app

# 运行 Flask 服务器
CMD ["python", "api.py"]
