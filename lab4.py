import sys
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def ajustar_clave(key_bytes, tamaño_esperado):
    """
    Ajusta la clave al tamaño requerido por el algoritmo.
    Rellena si es corta , trunca si es larga.
    """
    if len(key_bytes) < tamaño_esperado:
        padding = get_random_bytes(tamaño_esperado - len(key_bytes))
        return key_bytes + padding
    elif len(key_bytes) > tamaño_esperado:
        return key_bytes[:tamaño_esperado]
    return key_bytes

def ejecutar_algoritmo(nombre, key_size, iv_size, cipher_module, ajustar_paridad=False):
    print(f"\n=== {nombre} ===")
    try:
        key_str = input("Ingrese la Key (texto): ")
        iv_str = input("Ingrese el IV (texto): ")
        texto_str = input("Ingrese el Texto a cifrar: ")

        key_bytes = key_str.encode('utf-8')
        iv_bytes = iv_str.encode('utf-8')
        texto_bytes = texto_str.encode('utf-8')

        clave_final = ajustar_clave(key_bytes, key_size)
        if ajustar_paridad:
            try:
                clave_final = cipher_module.adjust_key_parity(clave_final)
            except AttributeError:
                pass
        print(f"\n[Ajuste] Clave original (bytes): {key_bytes}")
        print(f"[Ajuste] Clave final utilizada ({len(clave_final)} bytes): {clave_final.hex()}")

        if len(iv_bytes) != iv_size:
            print(f"[Ajuste] IV original (bytes): {iv_bytes}")
            iv_final = ajustar_clave(iv_bytes, iv_size)
            print(f"[Ajuste] IV final utilizado ({len(iv_final)} bytes): {iv_final.hex()}")
        else:
            iv_final = iv_bytes
            print(f"[Info] IV utilizado ({len(iv_final)} bytes): {iv_final.hex()}")

        print("\n--- Cifrando ---")
        cipher_encrypt = cipher_module.new(clave_final, cipher_module.MODE_CBC, iv_final)
        texto_cifrado = cipher_encrypt.encrypt(pad(texto_bytes, iv_size))
        print(f"Texto original: {texto_str}")
        print(f"Texto Cifrado (hex): {texto_cifrado.hex()}")

        print("\n--- Descifrando ---")
        cipher_decrypt = cipher_module.new(clave_final, cipher_module.MODE_CBC, iv_final)
        texto_descifrado_padded = cipher_decrypt.decrypt(texto_cifrado)
        texto_descifrado_bytes = unpad(texto_descifrado_padded, iv_size)
        texto_descifrado = texto_descifrado_bytes.decode('utf-8')
        print(f"Texto Descifrado: {texto_descifrado}")

        if texto_descifrado == texto_str:
            print("\nVERIFICACIÓN: Éxito. El texto descifrado coincide con el original.")
        else:
            print("\nVERIFICACIÓN: Error. El texto descifrado NO coincide.")

    except ValueError as e:
        print(f"\nError durante el (des)cifrado ({nombre}): {e}")
        print("Esto puede ocurrir si la clave/IV no son válidos o si el padding está corrupto.")
    except Exception as e:
        print(f"Ocurrió un error inesperado en {nombre}: {e}")


def main():
    print("--- Cifrador/Descifrador (AES-256, DES, 3DES) ---")

    ejecutar_algoritmo("AES-256", key_size=32, iv_size=16, cipher_module=AES, ajustar_paridad=False)
    ejecutar_algoritmo("DES", key_size=8, iv_size=8, cipher_module=DES, ajustar_paridad=True)
    ejecutar_algoritmo("3DES", key_size=24, iv_size=8, cipher_module=DES3, ajustar_paridad=True)

if __name__ == "__main__":
    main()