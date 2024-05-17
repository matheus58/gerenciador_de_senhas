import getpass
import json
import os

from cryptography.fernet import Fernet
from passlib.hash import pbkdf2_sha256 as pb

# Caminho do arquivo JSON
file_name = "./senhas.json"

# Funções


def gerar_chave():
    chave = Fernet.generate_key()
    with open("chave.key", "wb") as chave_file:
        chave_file.write(chave)
    return chave


def carregar_chave():
    return open("chave.key", "rb").read()


def verificar_master_password(senha_digitada, master_hash):
    return pb.verify(senha_digitada, master_hash)


def print_menu():
    print("Menu:")
    print("1. Adicionar senha")
    print("2. Ver senhas")
    print("3. Editar senha")
    print("4. Apagar senha")
    print("5. Mudar senha master")
    print("6. Sair")


def adicionar_senha(data):
    site = input("Digite o site: ")
    user = input("Digite o nome de usuário (ou email): ")
    senha = getpass.getpass("Digite a senha salva no site: ")
    senha_criptografada = fernet.encrypt(senha.encode()).decode()
    nova_senha = {"site": site, "username": user, "password": senha_criptografada}
    data["senhas"].append(nova_senha)


def ver_senhas(data):
    # Imprimir cabeçalho
    print("{:<20} {:<20} {:<20}".format("Site", "Usuário", "Senha"))
    print("-" * 60)
    # Imprimir senhas em colunas
    for index, senha in enumerate(data["senhas"]):
        site = senha["site"]
        username = senha["username"]
        password_criptografada = senha["password"]
        try:
            password = fernet.decrypt(password_criptografada.encode()).decode()
        except Exception as e:
            print(f"Erro ao descriptografar a senha para {site}: {e}")
            password = "Erro de descriptografia"
        print("{:<20} {:<20} {:<20} {:<5}".format(site, username, password, index))


def editar_senha(data):
    ver_senhas(data)
    try:
        index = int(input("Digite o índice da senha que deseja editar: "))
        if 0 <= index < len(data["senhas"]):
            site = input("Digite o novo site (ou pressione Enter para manter o atual): ")
            user = input(
                "Digite o novo nome de usuário (ou email) (ou pressione Enter para manter o atual): "
            )
            senha = getpass.getpass(
                "Digite a nova senha (ou pressione Enter para manter a atual): "
            )

            if site:
                data["senhas"][index]["site"] = site
            if user:
                data["senhas"][index]["username"] = user
            if senha:
                senha_criptografada = fernet.encrypt(senha.encode()).decode()
                data["senhas"][index]["password"] = senha_criptografada

            print("Senha atualizada com sucesso.")
        else:
            print("Índice inválido.")
    except ValueError:
        print("Entrada inválida. Por favor, insira um número válido.")


def apagar_senha(data):
    ver_senhas(data)
    try:
        index = int(input("Digite o índice da senha que deseja apagar: "))
        if 0 <= index < len(data["senhas"]):
            data["senhas"].pop(index)
            print("Senha apagada com sucesso.")
        else:
            print("Índice inválido.")
    except ValueError:
        print("Entrada inválida. Por favor, insira um número válido.")


def mudar_senha_master(data):
    senha_atual = getpass.getpass("Digite a senha master atual: ")
    if verificar_master_password(senha_atual, data["master_password"]["hash"]):
        nova_senha = getpass.getpass("Digite a nova senha master: ")
        nova_senha_confirmacao = getpass.getpass("Confirme a nova senha master: ")
        if nova_senha == nova_senha_confirmacao:
            novo_hash = pb.hash(nova_senha)
            data["master_password"]["hash"] = novo_hash
            print("Senha master atualizada com sucesso.")
        else:
            print("As senhas não coincidem. Tente novamente.")
    else:
        print("Senha master atual incorreta.")


def carregar_dados(file_name):
    if not os.path.exists(file_name) or os.path.getsize(file_name) == 0:
        # Se o arquivo não existir ou estiver vazio, inicialize com um JSON padrão
        master_password = getpass.getpass("Crie uma senha master: ")
        master_hash = pb.hash(master_password)
        data = {"master_password": {"hash": master_hash}, "senhas": []}
        with open(file_name, "w") as f:
            json.dump(data, f, indent=4)
    else:
        with open(file_name, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                print(f"Erro ao carregar o JSON: {e}")
                raise
    return data


def salvar_dados(data, file_name):
    with open(file_name, "w") as f:
        json.dump(data, f, indent=4)


def main():
    global fernet

    # Carregar a chave de criptografia
    if not os.path.exists("chave.key"):
        chave = gerar_chave()
    else:
        chave = carregar_chave()

    fernet = Fernet(chave)

    # Carrega o JSON
    data = carregar_dados(file_name)

    MASTER_HASH = data["master_password"]["hash"]

    senha = getpass.getpass("Digite a senha master: ")
    if verificar_master_password(senha, MASTER_HASH):
        while True:
            print_menu()
            requisicao = input("=> ")
            if requisicao == "6":
                break
            elif requisicao == "2":
                ver_senhas(data)
            elif requisicao == "1":
                adicionar_senha(data)
                # Salva o JSON atualizado
                salvar_dados(data, file_name)
            elif requisicao == "3":
                editar_senha(data)
                # Salva o JSON atualizado
                salvar_dados(data, file_name)
            elif requisicao == "4":
                apagar_senha(data)
                # Salva o JSON atualizado
                salvar_dados(data, file_name)
            elif requisicao == "5":
                mudar_senha_master(data)
                # Salva o JSON atualizado
                salvar_dados(data, file_name)
            else:
                print("Opção inválida.")
    else:
        print("Senha Master incorreta")


if __name__ == "__main__":
    main()
