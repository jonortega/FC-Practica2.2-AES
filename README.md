# Actividad 2

## Comandos usados

- Mirar tipo de fichero: `file encript_file`
- Mostrar strings dentro del fichero: `strings encript_file`
- Habilitar ejecución: `chmod -x encript_file`
- Hacer un test de cómo funciona: `./encript_file test.txt test.ecrypt`<

## Posibles algoritmos de encriptado usados

- Sabemos que es **AES**
- Longitud? 128, 192, 256
- Sistema usado si es de longitud grande? ECB, CBC, CTR

## Preguntas planteadas

- En CTR no se añade paddin, así que el fichero encriptado no tiene por qué tener una longitud que sea múltiplo de 16B. En nuestro caso siempre se generan múltiplos de 16B, por lo que **no usa CTR**.
- Si creamos un fichero con 16 "a" seguidos y luego otros 16 "a", si el fichero resultado encriptado tiene loques de valores cifrados idénticos, usa ECB. En este caso salen cosas aleatorias, por lo que **no usa ECB**.
- Haciendo pruebas, hemos visto que, al introducir la clave de crifrado, a partir de 4 caracteres el programa siempre cifra de la misma manera. Es decir, **siempre usa una clave igual o menor que longitud 4**.
- Hemos "llamado" a Kutxabank y nos han dicho lo siguiente: En todos los mensajes encriptados tienen una watermark al inicio que son 16Bytes y es la misma en todos. Ese watermark es **ownedbykutxabank**.
- Si miramos dentro del fichero encrypt_file, vemos que hay un sitio donde pone "privatekeyaescypherkutxabank" y luego faltan 4B para llegar a 32B. Podemos hacer la hipótesis de que la lave es "**privatekeyaescypherkutxabank____**" y los 4 dígitos que se cogen de la clave que te pide el programa son los que se pone al final para completar la clave. Con esto podemos saber también que se ha usado **AES-256** (32B -> 256b)
- La de Kutxabank nos vuelve a decir: **la IV era constante** y es lo que ponía después de la clave: `00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F`

## Cómo obtener la clave

- Sabemos que usa AES-256 CBC
- Sabemos la IV: `00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F`
- Sabemos que los primeros 16B son "ownedbykutxabank"
- Iterando todas las combinaciones posibles, se puede ver si sale el mismo bloque cifrado que los primeros 16B del fichero cifrado.
- Número de iteraciones max: 2^32 (4 dígitos, cada dígito 1B=8b -> 4x8=32b)
- Crear un bucle, teniendo como entrada un fichero con la watermark, encriptarlo y comprobar si sale lo mismo que los primeros 16B del fichero encriptado. Iterar todas las combinaciones de 4 dígitos posibles.
- La clave es de tipo unsigned char -> 32 posiciones -> Iterar en las últimas 4 posiciones

## decrypt.c

- Compilar el programa: `gcc -o decrypt decrypt.c aes.c`
- Ejecutar el programa: `./decrypt KEY KEY_MASK PLAINTEXT PLAINTEST_MASK CIPHER_TEXT`
  - `KEY`: k en hex `307072306976613074656B6530796165736379706865726B7574786162616E6B`
  - `KEY_MASK`: 00_03_07_12
  - `PLAINTEXT`: m0 en hex `504B0304140000080000`
  - `PLAINTEXT_MASK`: -1
  - `CIPHER_TEXT`: c0 en hex `DF14E0D9F0F8789B387312B39FB57927`
- Ejecutar rellenado: `./decrypt 307072306976613074656B6530796165736379706865726B7574786162616E6B 00_03_07_12 504B0304140000080000 -1 DF14E0D9F0F8789B387312B39FB57927`

## Librería AES_NI

1. Añadir carpeta libaesni (descomprimida).
2. #include "libaesni/iaesni.h"
3. Compilar: `gcc -o decrypt decrypt.c aes.c libaesni/libaes_lin64.so -DAESNI`
4. En la función `search()`:
   ```{c}
   #ifdefAESNI
    // llamadas a funciones AESNI -> iaesni.h (besni.c)?
   #else
    // Mantener llamadas a la librería tiny_AES
   #endif
   ```