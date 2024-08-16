import secrets
import string
from cryptography.fernet import Fernet

class GeradorDeSenhas:
    """
    Classe responsável por gerar senhas seguras com base nos critérios definidos.
    """
    def __init__(self, comprimento=12, usar_maiusculas=True, usar_digitos=True, usar_simbolos=True):
        """
        Inicializa o gerador de senhas com os parâmetros fornecidos.
        
        :param comprimento: Comprimento da senha gerada.
        :param usar_maiusculas: Se True, inclui letras maiúsculas na senha.
        :param usar_digitos: Se True, inclui dígitos na senha.
        :param usar_simbolos: Se True, inclui símbolos na senha.
        """
        self.comprimento = comprimento
        self.usar_maiusculas = usar_maiusculas
        self.usar_digitos = usar_digitos
        self.usar_simbolos = usar_simbolos

    def gerar_senha(self):
        """
        Gera uma senha aleatória com base nos critérios definidos.

        :return: Senha gerada.
        """
        caracteres = string.ascii_lowercase  # Inicia com letras minúsculas
        if self.usar_maiusculas:
            caracteres += string.ascii_uppercase  # Adiciona letras maiúsculas, se solicitado
        if self.usar_digitos:
            caracteres += string.digits  # Adiciona dígitos, se solicitado
        if self.usar_simbolos:
            caracteres += string.punctuation  # Adiciona símbolos, se solicitado
        
        senha = ''.join(secrets.choice(caracteres) for _ in range(self.comprimento))  # Gera a senha aleatória
        return senha

    def avaliar_forca_senha(self, senha):
        """
        Avalia a força da senha gerada com base em diferentes critérios.

        :param senha: Senha a ser avaliada.
        :return: Nível de força da senha (0 a 4).
        """
        forca = 0
        if any(c.islower() for c in senha):
            forca += 1
        if any(c.isupper() for c in senha):
            forca += 1
        if any(c.isdigit() for c in senha):
            forca += 1
        if any(c in string.punctuation for c in senha):
            forca += 1
        return forca

class Criptografia:
    """
    Classe responsável por criptografar e descriptografar senhas.
    """
    @staticmethod
    def gerar_chave():
        """
        Gera uma chave de criptografia para uso com Fernet.

        :return: Chave de criptografia gerada.
        """
        return Fernet.generate_key()

    @staticmethod
    def salvar_chave(chave, arquivo):
        """
        Salva a chave de criptografia em um arquivo.

        :param chave: Chave de criptografia a ser salva.
        :param arquivo: Nome do arquivo onde a chave será salva.
        """
        with open(arquivo, "wb") as chave_arquivo:
            chave_arquivo.write(chave)

    @staticmethod
    def carregar_chave(arquivo):
        """
        Carrega a chave de criptografia de um arquivo.

        :param arquivo: Nome do arquivo de onde a chave será carregada.
        :return: Chave de criptografia carregada.
        """
        with open(arquivo, "rb") as chave_arquivo:
            return chave_arquivo.read()

    @staticmethod
    def criptografar_senha(senha, chave):
        """
        Criptografa a senha usando a chave fornecida.

        :param senha: Senha a ser criptografada.
        :param chave: Chave de criptografia a ser usada.
        :return: Senha criptografada.
        """
        fernet = Fernet(chave)
        senha_bytes = senha.encode()  # Converte a senha para bytes
        senha_criptografada = fernet.encrypt(senha_bytes)  # Criptografa a senha
        return senha_criptografada

    @staticmethod
    def descriptografar_senha(senha_criptografada, chave):
        """
        Descriptografa a senha criptografada usando a chave fornecida.

        :param senha_criptografada: Senha criptografada a ser descriptografada.
        :param chave: Chave de criptografia a ser usada.
        :return: Senha descriptografada.
        """
        fernet = Fernet(chave)
        senha_bytes = fernet.decrypt(senha_criptografada)  # Descriptografa a senha
        return senha_bytes.decode()  # Converte os bytes de volta para string

def main():
    """
    Função principal que executa o programa.
    """
    comprimento = int(input("Comprimento da senha: "))  # Solicita o comprimento da senha ao usuário
    
    gerador = GeradorDeSenhas(comprimento=comprimento)  # Cria uma instância do gerador de senhas
    senha = gerador.gerar_senha()  # Gera a senha
    print(f"Senha gerada: {senha}")
    
    forca = gerador.avaliar_forca_senha(senha)  # Avalia a força da senha
    print(f"Força da senha: {forca}/4")
    
    chave = Criptografia.gerar_chave()  # Gera uma chave de criptografia
    Criptografia.salvar_chave(chave, "chave.key")  # Salva a chave em um arquivo
    
    senha_criptografada = Criptografia.criptografar_senha(senha, chave)  # Criptografa a senha
    print(f"Senha criptografada: {senha_criptografada}")
    
    chave = Criptografia.carregar_chave("chave.key")  # Carrega a chave do arquivo
    senha_descriptografada = Criptografia.descriptografar_senha(senha_criptografada, chave)  # Descriptografa a senha
    print(f"Senha descriptografada: {senha_descriptografada}")

if __name__ == "__main__":
    main()
