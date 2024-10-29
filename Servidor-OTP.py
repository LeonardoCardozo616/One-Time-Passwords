import hashlib
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
        otps.append(base[:tamanho])  # Trunca para o tamanho desejado
    return otps

# Função para criar base de dados do servidor
def criar_base_servidor(usuario, senha_semente, salt):
    senha_semente_hash = gerar_hash(senha_semente)
    salt_hash = gerar_hash(salt)
    
    # Armazenamento em arquivo
    with open("base_servidor.txt", "w") as f:
        f.write(f"Nome: {usuario}\n")
        f.write(f"Semente Hash: {senha_semente_hash}\n")
        f.write(f"Salt Hash: {salt_hash}\n")
    print("Base de dados do servidor criada.")

# Função de validação de OTP
def validar_otp(nome, senha, senha_semente, salt, otps_usadas):
    senha_semente_hash = gerar_senha_semente_hash(senha_semente, salt)
    timestamp = time.strftime("%Y%m%d%H%M")  # Timestamp do minuto atual
    
    # Gera a lista de OTPs para o minuto atual
    otps_validas = gerar_otps(senha_semente_hash, timestamp)
    
    if senha in otps_validas and senha not in otps_usadas:
        # Se a senha estiver na lista válida e não foi usada antes
        otps_usadas.add(senha)  # Adiciona a senha ao conjunto de senhas usadas
        print("Chave válida.")
    else:
        print("Erro: Chave inválida ou já utilizada.")

# Função principal para iniciar o servidor
def iniciar_servidor():
    # Dados iniciais
    usuario = input("Login: ")
    senha_semente = input("Senha semente: ")
    salt = input("Salt: ")
    otps_usadas = set()  # Armazena as OTPs que já foram usadas
    
    # Cria a base de dados do servidor
    criar_base_servidor(usuario, senha_semente, salt)
    
    # Ciclo de verificação da senha (simula múltiplas tentativas)
    while True:
        senha = input("Digite a senha OTP: ")
        validar_otp(usuario, senha, senha_semente, salt, otps_usadas)

if __name__ == "__main__":
    iniciar_servidor()
