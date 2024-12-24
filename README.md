# LATIHAN JWT AUTHENTICATION DENGAN SPRING BOOT
Pada latihan ini saya membuat api untuk authentication memakai JWT. Untuk auth nya ada sign up, sign in, logout, dan ada refresh token / cookie.

## Sign-Up
- Endpoint : http://localhost:8080/sign-up
- Method : POST

  ![image](https://github.com/user-attachments/assets/3f88f954-8373-431f-9ea5-40374e87fecf)

## Sign-in
- Endpoint : http://localhost:8080/sign-in
- Method : POST
  
  ![image](https://github.com/user-attachments/assets/0b3312af-84df-43c9-9fbe-e89d586e2ef3)

## Access Message pake Access Token
- Endpoint : http://localhost:8080/api/admin-message?message=Hello
- Method : GET

![image](https://github.com/user-attachments/assets/9e08c77b-d6ac-4a54-8535-3a4bd6abae8e)

## Refresh token atau cookie untuk mengambil kembali accees token yang sudah expired
- Endpoint : http://localhost:8080/refresh-token
- Method : POST

![image](https://github.com/user-attachments/assets/8d5640d6-d0bc-4780-b476-82e8db7f8a6e)

## logout
- Endpoint : http://localhost:8080/logout
- Method : POST

  ![image](https://github.com/user-attachments/assets/48b46fb2-4e48-45c5-89a3-ab8b755f6cc2)



## References

- Special thanks to [atquil/spring-security](https://github.com/atquil/spring-security) for their excellent repository, which provided valuable insights during the project development.




