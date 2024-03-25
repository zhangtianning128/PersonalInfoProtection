# PersonalInfoProtection
1. Run the blockchain service program (open 3 terminals, start 3 services):

   ```bash
   python.exe blockchain/blockchain_server.py
   ```

2. Test the functionality of the blockchain service program:
   (1) Create chain:

   ```bash
   python.exe blockchain_test/create_chain.py
   ```
   (2) Fetch chain:

   ```bash
   python.exe blockchain_test/get_chain.py
   ```
   (3) Add transaction:

   ```bash
   python.exe blockchain_test/add_transaction.py
   ```

3. Create a Docker network:
   First, create a Docker network to ensure secure communication between the database and application containers.

   ```bash
   docker network create my_network
   ```

4. Create a Docker volume:
   Next, create a Docker volume to persist database data.

   ```bash
   docker volume create db_data
   ```

5. Run the database container:
   Run a PostgreSQL database container:

   ```bash
   docker run --name db_container --network my_network -v db_data:/var/lib/postgresql/data -e POSTGRES_PASSWORD=mysecretpassword -d postgres
   ```

6. Build the privacy data writing container:
   Switch to the app1 directory and build:

   ```bash
   docker build -t my-write-container .
   ```

7. Run the writing container without exposing any ports and connect to the custom network:

   ```bash
   docker run --network my-custom-network my-write-container
   ```

8. Build the privacy data access and transmission container:
   Switch to the app3 directory and build:

   ```bash
   docker build -t my-app-container .
   ```

9. Run the privacy data access and transmission container:

   ```bash
   docker run -p 8080:5000 --network my-custom-network my-app-container
   ```

10. Test the container's operation:

    ```bash
    python.exe app3/test.py
    ```

11. Run the decryption participant program (open 3 terminals, start 3 services):

    ```bash
    python.exe participant/decrypt_part.py
    ```

12. Run the decryption program:

    ```bash
    python.exe decrypter/api.py
    ```

13. Login to trigger the process:

    ```bash
    python.exe app3/test.py
    ```
