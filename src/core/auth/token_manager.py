import bcrypt
from datetime import datetime

def calcular_palavra_base():
    data_atual = datetime.now()
    hora_str = f"{data_atual.hour:02d}"
    segundo_digito_hora = int(hora_str[1])
    minuto_str = f"{data_atual.minute:02d}"
    primeiro_digito_minuto = int(minuto_str[0])

    primeiro_setor = f"{segundo_digito_hora}{primeiro_digito_minuto}"
    ano = data_atual.year
    mes = data_atual.month - 1
    if mes == 0:
        mes = 12
        ano -= 1
    dia = data_atual.day

    multiplicacao_data = dia * mes * ano
    resultado_quadrado = multiplicacao_data ** 2
    segundo_setor = str(resultado_quadrado)[:6]
    segundo_setor = segundo_setor.ljust(6, '0')

    horas_x_minutos = data_atual.hour * data_atual.minute
    quarto_digito_ano = int(str(data_atual.year)[3])
    terceiro_setor = str(horas_x_minutos * quarto_digito_ano)

    palavra_base = f"{primeiro_setor}{segundo_setor}{terceiro_setor}"
    return palavra_base

def gerar_token():
    try:
        palavra_base = calcular_palavra_base()
        salt_aleatorio = bcrypt.gensalt()
        token = bcrypt.hashpw(palavra_base.encode("utf-8"), salt_aleatorio)
        return token.decode("utf-8")
    except Exception as e:
        print(f"[TokenManager] Erro ao gerar token")
        return None

def validar_token(client_token):
    try:
        palavra_base_local = calcular_palavra_base()
        result = bcrypt.checkpw(palavra_base_local.encode(), client_token.encode())
        return result
    except Exception as e:
        return False

