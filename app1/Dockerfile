# Dockerfile for app1

# 使用官方的 Python 基础镜像
FROM python:3.7

# 设置工作目录
WORKDIR /app

# 安装依赖
RUN pip install cryptography sqlalchemy psycopg2-binary

# 复制代码和公钥文件到容器中
COPY create_and_store.py public_key.pem /app/

RUN ls /app

# 运行脚本
CMD ["python", "create_and_store.py"]
