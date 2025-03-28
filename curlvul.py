import subprocess
import re
import sys

def analisar_seguranca_http(url):
    """
    Analisa os cabeçalhos HTTP de um URL e indica a segurança das diretivas,
    colorindo "Seguro" de verde e "Inseguro" de vermelho.
    """

    comando = f"curl -s -I -L --compressed {url}"
    try:
        resultado = subprocess.check_output(comando, shell=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"\033[91mErro ao executar o comando curl: {e}\033[0m")  # Vermelho
        return

    linhas = resultado.splitlines()

    # Flags para controle de segurança
    status_seguro = False
    location_seguro = False
    csp_seguro = False
    hsts_seguro = False
    xss_seguro = False
    content_type_seguro = False
    referrer_policy_seguro = False
    permissions_policy_seguro = False
    clear_site_data_seguro = False
    coop_seguro = False
    corp_seguro = False
    coep_seguro = False

    print("--- Resposta do curl: --- \n")
    print(resultado)
    print("--- Análise da segurança: --- \n")

    primeiro_http = True  # Flag para rastrear o primeiro status HTTP
    cabecalhos_verificados = set()  # Conjunto para rastrear cabeçalhos verificados

    for linha in linhas:
        if re.match(r"^HTTP", linha, re.IGNORECASE) and primeiro_http:
            print(f"--- \033[94mNome do status\033[0m: {linha.strip()} ---")  # azul
            if "301 Moved Permanently" in linha:
                print(f"{linha.strip()} - \033[92mSeguro\033[0m \n")  # Verde
                status_seguro = True
            else:
                print(f"{linha.strip()} - \033[91mInseguro\033[0m \n")  # Vermelho
            primeiro_http = False
        elif re.match(r"^Location", linha, re.IGNORECASE):
            print(f"--- \033[94mConfiguração do location\033[0m para https indica um ponto de segurança ---")  # azul
            if "https://" in linha:
                print(f"{linha.strip()} - \033[92mSeguro\033[0m \n")  # Verde
                location_seguro = True
            else:
                print(f"{linha.strip()} - \033[91mInseguro\033[0m \n")  # Vermelho
        elif re.match(r"^content-security-policy", linha, re.IGNORECASE):
            if "content-security-policy" not in cabecalhos_verificados:
                print(f"--- \033[94mInstrui o navegador a atualizar todas as solicitações HTTP para HTTPS.\033[0m ---")  # azul
                if "upgrade-insecure-requests" in linha.lower():
                    print(f"{linha.strip()} - \033[92mSeguro\033[0m \n")  # Verde
                    csp_seguro = True
                else:
                    print(f"{linha.strip()} - \033[91mInseguro ou não encontrado: Mixed Content\033[0m")  # Vermelho
                cabecalhos_verificados.add("content-security-policy")
        elif re.match(r"^strict-transport-security", linha, re.IGNORECASE):
            if "strict-transport-security" not in cabecalhos_verificados:
                print(f"--- \033[94mHSTS ativo\033[0m ---")  # azul
                if "max-age" in linha.lower() and "includeSubDomains" in linha.lower():
                    print(f"{linha.strip()} - \033[92mSeguro (com subdomínios)\033[0m \n")
                    hsts_seguro = True
                elif "max-age" in linha.lower():
                    print(f"{linha.strip()} - \033[93mParcialmente seguro (sem subdomínios)\033[0m \n")
                    hsts_seguro = True
                else:
                    print(f"{linha.strip()} - \033[91mInseguro ou não encontrado: Ataques Man-in-the-Middle\033[0m")
                cabecalhos_verificados.add("strict-transport-security")
        elif re.match(r"^x-xss-protection", linha, re.IGNORECASE):
            if "x-xss-protection" not in cabecalhos_verificados:
                print(f"--- \033[94mProteção XSS ativa\033[0m ---")  # azul
                if "1; mode=block" in linha.lower():
                    print(f"{linha.strip()} - \033[92mSeguro\033[0m \n")
                    xss_seguro = True
                else:
                    print(f"{linha.strip()} - \033[91mInseguro ou não encontrado: XSS\033[0m \n")
                cabecalhos_verificados.add("x-xss-protection")
        elif re.match(r"^x-content-type-options", linha, re.IGNORECASE):
            if "x-content-type-options" not in cabecalhos_verificados:
                print(f"--- \033[94mPrevenção de MIME Sniffing ativa\033[0m ---")  # azul
                if "nosniff" in linha.lower():
                    print(f"{linha.strip()} - \033[92mSeguro\033[0m \n")
                    content_type_seguro = True
                else:
                    print(f"{linha.strip()} - \033[91mInseguro ou não encontrado: MIME Sniffing\033[0m \n")
                cabecalhos_verificados.add("x-content-type-options")
        elif re.match(r"^referrer-policy", linha, re.IGNORECASE):
            if "referrer-policy" not in cabecalhos_verificados:
                print(f"--- \033[94mControle de vazamento de informação via Referrer\033[0m ---")  # azul
                if "no-referrer" in linha.lower() or "strict-origin-when-cross-origin" in linha.lower():
                    print(f"{linha.strip()} - \033[92mSeguro\033[0m \n")
                    referrer_policy_seguro = True
                else:
                    print(f"{linha.strip()} - \033[91mInseguro ou não encontrado: Vazamento de informação\033[0m \n")
                cabecalhos_verificados.add("referrer-policy")
        elif re.match(r"^permissions-policy", linha, re.IGNORECASE):
            if "permissions-policy" not in cabecalhos_verificados:
                print(f"--- \033[94mControle de APIs e recursos do navegador\033[0m ---")  # azul
                if "geolocation=(), microphone=(), camera=()" in linha.lower():
                    print(f"{linha.strip()} - \033[92mSeguro\033[0m \n")
                    permissions_policy_seguro = True
                else:
                    print(f"{linha.strip()} - \033[93mParcialmente seguro (verificar configurações)\033[0m \n")
                cabecalhos_verificados.add("permissions-policy")
        elif re.match(r"^clear-site-data", linha, re.IGNORECASE):
            if "clear-site-data" not in cabecalhos_verificados:
                print(f"--- \033[94mLimpeza de dados do site\033[0m ---")  # azul
                if "\"*\"" in linha or "\"cookies\"" in linha:
                    print(f"{linha.strip()} - \033[92mSeguro\033[0m \n")
                    clear_site_data_seguro = True
                else:
                    print(f"{linha.strip()} - \033[93mConfiguração limitada\033[0m \n")
                cabecalhos_verificados.add("clear-site-data")
        elif re.match(r"^cross-origin-opener-policy", linha, re.IGNORECASE):
            if "cross-origin-opener-policy" not in cabecalhos_verificados:
                print(f"--- \033[94mIsolamento de janelas/tabs\033[0m ---")  # azul
                if "same-origin" in linha.lower():
                    print(f"{linha.strip()} - \033[92mSeguro\033[0m \n")
                    coop_seguro = True
                else:
                    print(f"{linha.strip()} - \033[91mInseguro ou não encontrado: Ataques via janelas\033[0m \n")
                cabecalhos_verificados.add("cross-origin-opener-policy")
        elif re.match(r"^cross-origin-resource-policy", linha, re.IGNORECASE):
            if "cross-origin-resource-policy" not in cabecalhos_verificados:
                print(f"--- \033[94mControle de acesso a recursos cross-origin\033[0m ---")  # azul
                if "same-origin" in linha.lower() or "same-site" in linha.lower():
                    print(f"{linha.strip()} - \033[92mSeguro\033[0m \n")
                    corp_seguro = True
                else:
                    print(f"{linha.strip()} - \033[91mInseguro ou não encontrado: Ataques via recursos\033[0m \n")
                cabecalhos_verificados.add("cross-origin-resource-policy")
        elif re.match(r"^cross-origin-embedder-policy", linha, re.IGNORECASE):
            if "cross-origin-embedder-policy" not in cabecalhos_verificados:
                print(f"--- \033[94mSegurança para recursos embutidos\033[0m ---")  # azul
                if "require-corp" in linha.lower():
                    print(f"{linha.strip()} - \033[92mSeguro\033[0m \n")
                    coep_seguro = True
                else:
                    print(f"{linha.strip()} - \033[91mInseguro ou não encontrado: Ataques via recursos embutidos\033[0m \n")
                cabecalhos_verificados.add("cross-origin-embedder-policy")

    total_testes = 13  # Atualizado para incluir os novos cabeçalhos
    seguros_encontrados = sum([
        status_seguro, location_seguro, csp_seguro, hsts_seguro, 
        xss_seguro, content_type_seguro, referrer_policy_seguro,
        permissions_policy_seguro, clear_site_data_seguro, coop_seguro,
        corp_seguro, coep_seguro
    ])
    inseguros_encontrados = total_testes - seguros_encontrados

    print(f"\n--- Resultado da análise: {seguros_encontrados}/{total_testes} pontos seguros encontrados ---")

    # Exibe os cabeçalhos inseguros ou não encontrados
    if not status_seguro:
        print("Status HTTP:\033[91m Inseguro\033[0m")
    if not location_seguro:
        print("Location:\033[91m Inseguro ou não encontrado.\033[0m Possível: Redirecionamento HTTP")
    if not csp_seguro:
        print("content-security-policy:\033[91m Inseguro ou não encontrado.\033[0m Possível: Mixed Content")
    if not hsts_seguro:
        print("strict-transport-security:\033[91m Inseguro ou não encontrado.\033[0m Possível: Ataques Man-in-the-Middle")
    if not xss_seguro:
        print("x-xss-protection:\033[91m Inseguro ou não encontrado.\033[0m Possível: XSS")
    if not content_type_seguro:
        print("x-content-type-options:\033[91m Inseguro ou não encontrado.\033[0m Possível: MIME Sniffing")
    if not referrer_policy_seguro:
        print("referrer-policy:\033[91m Inseguro ou não encontrado.\033[0m Possível: Vazamento de informação via Referrer")
    if not permissions_policy_seguro:
        print("permissions-policy:\033[91m Inseguro ou não encontrado.\033[0m Possível: Uso indevido de APIs sensíveis")
    if not clear_site_data_seguro:
        print("clear-site-data:\033[91m Inseguro ou não encontrado.\033[0m Possível: Dados persistentes após logout")
    if not coop_seguro:
        print("cross-origin-opener-policy:\033[91m Inseguro ou não encontrado.\033[0m Possível: Ataques via janelas")
    if not corp_seguro:
        print("cross-origin-resource-policy:\033[91m Inseguro ou não encontrado.\033[0m Possível: Ataques via recursos")
    if not coep_seguro:
        print("cross-origin-embedder-policy:\033[91m Inseguro ou não encontrado.\033[0m Possível: Ataques via recursos embutidos")

    if seguros_encontrados == 0:
        print("\n\033[91mNenhuma diretiva de segurança encontrada, site extremamente vulnerável.\033[0m")  # Vermelho
    elif seguros_encontrados < total_testes / 2:
        print("\n\033[93mSite com proteções básicas, mas várias vulnerabilidades importantes.\033[0m")  # Amarelo
    else:
        print("\n\033[92mSite com boa cobertura de proteções de segurança.\033[0m")  # Verde

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 curlsec.py dominio_a_ser_verificado")
        sys.exit(1)

    dominio = sys.argv[1]
    analisar_seguranca_http(dominio)