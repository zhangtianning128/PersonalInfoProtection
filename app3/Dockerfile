# Dockerfile for app3

# 使用官方的 Python 基础镜像
FROM python:3.7

# 设置工作目录
WORKDIR /app

# 安装依赖
RUN pip install Flask SQLAlchemy PyJWT Pillow psycopg2 cryptography

RUN pip install LSBSteg numpy requests

RUN apt-get update && apt-get install -y libgl1-mesa-glx

# 复制代码和公钥文件到容器中
COPY api.py private_key.pem second_party_public_key.pem public_key_1.pem public_key_2.pem public_key_3.pem /app/

RUN ls /app

# 运行脚本
CMD ["python", "api.py"]
