import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import time
import os

# Função para gerar hash SHA-256
def gerar_hash(senha):
    return hashlib.sha256(senha.encode('utf-8')).hexdigest()

# Função para gerar hash da senha semente e salt
def gerar_senha_semente_hash(senha_semente, salt):
    hash_semente = gerar_hash(senha_semente)
    hash_salt = gerar_hash(salt)
    return gerar_hash(hash_semente + hash_salt)

# Função para gerar OTPs para um minuto específico
def gerar_otps(senha_semente_hash, timestamp, num_otps=5, tamanho=6):
    otps = []
    base = gerar_hash(senha_semente_hash + timestamp)
    for _ in range(num_otps):
        base = gerar_hash(base)
        otps.append(base[:tamanho])  # Trunca para o tamanho desejado (6 ou 8)
    return otps

# Função de criptografia AES para a base de dados
def criptografar_dados(dados, senha_local):
    chave = gerar_hash(senha_local)[:32].encode('utf-8')  # 256 bits para AES
    iv = os.urandom(16)  # Gera um IV aleatório de 16 bytes
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Adiciona padding aos dados
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    dados_padded = padder.update(dados.encode('utf-8')) + padder.finalize()

    # Criptografa os dados
    dados_criptografados = encryptor.update(dados_padded) + encryptor.finalize()
    return iv + dados_criptografados

# Função de descriptografia AES
def descriptografar_dados(dados_criptografados, senha_local):
    chave = gerar_hash(senha_local)[:32].encode('utf-8')
    iv = dados_criptografados[:16]
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Descriptografa os dados
    dados_padded = decryptor.update(dados_criptografados[16:]) + decryptor.finalize()

    # Remove o padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    dados = unpadder.update(dados_padded) + unpadder.finalize()
    return dados.decode('utf-8')

# Exemplo de uso do sistema de geração de OTP
def main():
    # Definições iniciais
    entrada = input("Deseja \"cadastrar\" ou fazer \"login\"? ")
    if entrada == "cadastrar":
        usuario = input("Login: ")
        senha_semente = input("Senha semente: ")
        salt = input("Salt: ")
        senha_local = input("Senha local: ")
        
        # Gerar hash da senha semente combinada com o salt
        senha_semente_hash = gerar_senha_semente_hash(senha_semente, salt)

        # Criptografar e armazenar dados (usuário e hash da senha semente)
        dados_para_criptografar = usuario + ':' + senha_semente_hash
        dados_criptografados = criptografar_dados(dados_para_criptografar, senha_local)
        
        # Salva dados criptografados no arquivo local
        with open("base_dados_criptografada.bin", "wb") as f:
            f.write(dados_criptografados)
        
        print("Cadastro realizado com sucesso.")

    else:
        usuario = input("Login: ")
        senha_local = input("Senha local: ")

        # Carregar e tentar descriptografar os dados
        try:
            with open("base_dados_criptografada.bin", "rb") as f:
                dados_lidos = f.read()
            dados_descriptografados = descriptografar_dados(dados_lidos, senha_local)
            
            # Separar o usuário e o hash da senha semente armazenados
            usuario_armazenado, senha_semente_hash = dados_descriptografados.split(':')
            
            # Verificar se o usuário inserido corresponde ao armazenado
            if usuario != usuario_armazenado:
                print("Erro: Usuário ou senha incorretos ou base de dados não encontrada.")
                return
            
            print("Autenticado com sucesso. Gerando OTPs a cada minuto:")

            # Loop para gerar OTPs a cada minuto
            while True:
                # Obter o timestamp até o minuto atual
                timestamp = time.strftime("%Y%m%d%H%M")
                lista_otps = gerar_otps(senha_semente_hash, timestamp)
                
                print("Lista de OTPs geradas:", lista_otps)

                # Espera 1 minuto até a próxima geração de OTPs
                time.sleep(60)

        except (FileNotFoundError, ValueError):
            print("Erro: Usuário ou senha incorretos ou base de dados não encontrada.")
            return

if __name__ == "__main__":
    main()
