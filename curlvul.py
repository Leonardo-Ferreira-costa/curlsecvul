import subprocess
import re
import sys
import os
from io import StringIO
import contextlib
import datetime

def analisar_seguranca_http(url, para_arquivo=False):
    """
    Analisa os cabeçalhos HTTP de um URL e indica a segurança das diretivas.
    Parâmetros:
    - url: URL a ser analisada
    - para_arquivo: Se True, remove cores ANSI do output
    """
    # Definição de cores para o terminal (vazias se for para arquivo)
    if para_arquivo:
        VERDE = ""
        VERMELHO = ""
        AMARELO = ""
        AZUL = ""
        RESET = ""
    else:
        VERDE = "\033[92m"
        VERMELHO = "\033[91m"
        AMARELO = "\033[93m"
        AZUL = "\033[94m"
        RESET = "\033[0m"

    # Capturar a saída em uma string em vez de imprimir diretamente
    output = StringIO()
    with contextlib.redirect_stdout(output):
        data_hora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        separador = "="*80
        print(separador)
        print(f"ANÁLISE DE SEGURANÇA HTTP - {url}")
        print(f"Data/Hora: {data_hora}")
        print(separador)
        
        comando = f"curl -s -I -L --compressed {url}"
        try:
            resultado = subprocess.check_output(comando, shell=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"\n[ERRO] Falha ao acessar {url}: {e}\n")
            print(separador)
            return output.getvalue()

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

        # Seção 1: Cabeçalhos HTTP
        print("\n1. CABEÇALHOS HTTP RECEBIDOS")
        print("-" * 40)
        print(resultado)

        # Seção 2: Análise detalhada
        print("\n2. ANÁLISE DETALHADA DE SEGURANÇA")
        print("-" * 40)

        primeiro_http = True  # Flag para rastrear o primeiro status HTTP
        cabecalhos_verificados = set()  # Conjunto para rastrear cabeçalhos verificados

        for linha in linhas:
            if re.match(r"^HTTP", linha, re.IGNORECASE) and primeiro_http:
                print(f"[Status HTTP] {linha.strip()}")
                if "301 Moved Permanently" in linha:
                    print(f"► Estado: {VERDE}Seguro{RESET}")
                    status_seguro = True
                else:
                    print(f"► Estado: {VERMELHO}Inseguro{RESET}")
                primeiro_http = False
                print()
            elif re.match(r"^Location", linha, re.IGNORECASE):
                print(f"[Redirecionamento] {linha.strip()}")
                if "https://" in linha:
                    print(f"► Estado: {VERDE}Seguro{RESET} (Redireciona para HTTPS)")
                    location_seguro = True
                else:
                    print(f"► Estado: {VERMELHO}Inseguro{RESET} (Não redireciona para HTTPS)")
                print()
            elif re.match(r"^content-security-policy", linha, re.IGNORECASE):
                if "content-security-policy" not in cabecalhos_verificados:
                    print(f"[Content-Security-Policy]")
                    if "upgrade-insecure-requests" in linha.lower():
                        print(f"► Estado: {VERDE}Seguro{RESET} (Previne conteúdo misto)")
                        csp_seguro = True
                    else:
                        print(f"► Estado: {VERMELHO}Inseguro{RESET} (Possível conteúdo misto)")
                    print(f"► Valor: {linha.split(':', 1)[1].strip()}")
                    cabecalhos_verificados.add("content-security-policy")
                    print()
            elif re.match(r"^strict-transport-security", linha, re.IGNORECASE):
                if "strict-transport-security" not in cabecalhos_verificados:
                    print(f"[Strict-Transport-Security (HSTS)]")
                    if "max-age" in linha.lower() and "includeSubDomains" in linha.lower():
                        print(f"► Estado: {VERDE}Seguro{RESET} (Com proteção de subdomínios)")
                        hsts_seguro = True
                    elif "max-age" in linha.lower():
                        print(f"► Estado: {AMARELO}Parcialmente seguro{RESET} (Sem proteção de subdomínios)")
                        hsts_seguro = True
                    else:
                        print(f"► Estado: {VERMELHO}Inseguro{RESET} (Configuração inadequada)")
                    print(f"► Valor: {linha.split(':', 1)[1].strip()}")
                    cabecalhos_verificados.add("strict-transport-security")
                    print()
            elif re.match(r"^x-xss-protection", linha, re.IGNORECASE):
                if "x-xss-protection" not in cabecalhos_verificados:
                    print(f"[X-XSS-Protection]")
                    if "1; mode=block" in linha.lower():
                        print(f"► Estado: {VERDE}Seguro{RESET} (Proteção XSS ativada)")
                        xss_seguro = True
                    else:
                        print(f"► Estado: {VERMELHO}Inseguro{RESET} (Vulnerável a XSS)")
                    print(f"► Valor: {linha.split(':', 1)[1].strip()}")
                    cabecalhos_verificados.add("x-xss-protection")
                    print()
            elif re.match(r"^x-content-type-options", linha, re.IGNORECASE):
                if "x-content-type-options" not in cabecalhos_verificados:
                    print(f"[X-Content-Type-Options]")
                    if "nosniff" in linha.lower():
                        print(f"► Estado: {VERDE}Seguro{RESET} (Previne MIME sniffing)")
                        content_type_seguro = True
                    else:
                        print(f"► Estado: {VERMELHO}Inseguro{RESET} (Vulnerável a MIME sniffing)")
                    print(f"► Valor: {linha.split(':', 1)[1].strip()}")
                    cabecalhos_verificados.add("x-content-type-options")
                    print()
            elif re.match(r"^referrer-policy", linha, re.IGNORECASE):
                if "referrer-policy" not in cabecalhos_verificados:
                    print(f"[Referrer-Policy]")
                    if "no-referrer" in linha.lower() or "strict-origin-when-cross-origin" in linha.lower():
                        print(f"► Estado: {VERDE}Seguro{RESET} (Previne vazamento de informação)")
                        referrer_policy_seguro = True
                    else:
                        print(f"► Estado: {VERMELHO}Inseguro{RESET} (Possível vazamento de informação)")
                    print(f"► Valor: {linha.split(':', 1)[1].strip()}")
                    cabecalhos_verificados.add("referrer-policy")
                    print()
            elif re.match(r"^permissions-policy", linha, re.IGNORECASE):
                if "permissions-policy" not in cabecalhos_verificados:
                    print(f"[Permissions-Policy]")
                    if "geolocation=(), microphone=(), camera=()" in linha.lower():
                        print(f"► Estado: {VERDE}Seguro{RESET} (Restringe APIs sensíveis)")
                        permissions_policy_seguro = True
                    else:
                        print(f"► Estado: {AMARELO}Parcialmente seguro{RESET} (Verificar configurações)")
                    print(f"► Valor: {linha.split(':', 1)[1].strip()}")
                    cabecalhos_verificados.add("permissions-policy")
                    print()
            elif re.match(r"^clear-site-data", linha, re.IGNORECASE):
                if "clear-site-data" not in cabecalhos_verificados:
                    print(f"[Clear-Site-Data]")
                    if "\"*\"" in linha or "\"cookies\"" in linha:
                        print(f"► Estado: {VERDE}Seguro{RESET} (Limpa dados sensíveis)")
                        clear_site_data_seguro = True
                    else:
                        print(f"► Estado: {AMARELO}Parcialmente seguro{RESET} (Limitado)")
                    print(f"► Valor: {linha.split(':', 1)[1].strip()}")
                    cabecalhos_verificados.add("clear-site-data")
                    print()
            elif re.match(r"^cross-origin-opener-policy", linha, re.IGNORECASE):
                if "cross-origin-opener-policy" not in cabecalhos_verificados:
                    print(f"[Cross-Origin-Opener-Policy (COOP)]")
                    if "same-origin" in linha.lower():
                        print(f"► Estado: {VERDE}Seguro{RESET} (Isola janelas/tabs)")
                        coop_seguro = True
                    else:
                        print(f"► Estado: {VERMELHO}Inseguro{RESET} (Possíveis ataques via janelas)")
                    print(f"► Valor: {linha.split(':', 1)[1].strip()}")
                    cabecalhos_verificados.add("cross-origin-opener-policy")
                    print()
            elif re.match(r"^cross-origin-resource-policy", linha, re.IGNORECASE):
                if "cross-origin-resource-policy" not in cabecalhos_verificados:
                    print(f"[Cross-Origin-Resource-Policy (CORP)]")
                    if "same-origin" in linha.lower() or "same-site" in linha.lower():
                        print(f"► Estado: {VERDE}Seguro{RESET} (Controle de acesso a recursos)")
                        corp_seguro = True
                    else:
                        print(f"► Estado: {VERMELHO}Inseguro{RESET} (Possíveis ataques via recursos)")
                    print(f"► Valor: {linha.split(':', 1)[1].strip()}")
                    cabecalhos_verificados.add("cross-origin-resource-policy")
                    print()
            elif re.match(r"^cross-origin-embedder-policy", linha, re.IGNORECASE):
                if "cross-origin-embedder-policy" not in cabecalhos_verificados:
                    print(f"[Cross-Origin-Embedder-Policy (COEP)]")
                    if "require-corp" in linha.lower():
                        print(f"► Estado: {VERDE}Seguro{RESET} (Protege recursos embutidos)")
                        coep_seguro = True
                    else:
                        print(f"► Estado: {VERMELHO}Inseguro{RESET} (Possíveis ataques via recursos embutidos)")
                    print(f"► Valor: {linha.split(':', 1)[1].strip()}")
                    cabecalhos_verificados.add("cross-origin-embedder-policy")
                    print()

        # Seção 3: Resumo de cabeçalhos não encontrados
        print("\n3. CABEÇALHOS DE SEGURANÇA NÃO ENCONTRADOS")
        print("-" * 40)
        
        cabecalhos_ausentes = []
        
        if not status_seguro:
            cabecalhos_ausentes.append("Status HTTP (301 Moved Permanently)")
        if not location_seguro:
            cabecalhos_ausentes.append("Location (HTTPS)")
        if not csp_seguro:
            cabecalhos_ausentes.append("Content-Security-Policy")
        if not hsts_seguro:
            cabecalhos_ausentes.append("Strict-Transport-Security (HSTS)")
        if not xss_seguro:
            cabecalhos_ausentes.append("X-XSS-Protection")
        if not content_type_seguro:
            cabecalhos_ausentes.append("X-Content-Type-Options")
        if not referrer_policy_seguro:
            cabecalhos_ausentes.append("Referrer-Policy")
        if not permissions_policy_seguro:
            cabecalhos_ausentes.append("Permissions-Policy")
        if not clear_site_data_seguro:
            cabecalhos_ausentes.append("Clear-Site-Data")
        if not coop_seguro:
            cabecalhos_ausentes.append("Cross-Origin-Opener-Policy (COOP)")
        if not corp_seguro:
            cabecalhos_ausentes.append("Cross-Origin-Resource-Policy (CORP)")
        if not coep_seguro:
            cabecalhos_ausentes.append("Cross-Origin-Embedder-Policy (COEP)")
            
        if cabecalhos_ausentes:
            for cabecalho in cabecalhos_ausentes:
                print(f"▪ {VERMELHO}{cabecalho}{RESET}")
        else:
            print(f"▪ {VERDE}Todos os cabeçalhos de segurança estão presentes{RESET}")

        # Seção 4: Conclusão e pontuação
        total_testes = 13
        seguros_encontrados = sum([
            status_seguro, location_seguro, csp_seguro, hsts_seguro, 
            xss_seguro, content_type_seguro, referrer_policy_seguro,
            permissions_policy_seguro, clear_site_data_seguro, coop_seguro,
            corp_seguro, coep_seguro
        ])
        porcentagem = (seguros_encontrados / total_testes) * 100

        print("\n4. PONTUAÇÃO DE SEGURANÇA")
        print("-" * 40)
        print(f"► Pontuação: {seguros_encontrados}/{total_testes} ({porcentagem:.1f}%)")
        
        if seguros_encontrados == 0:
            print(f"► Conclusão: {VERMELHO}SITE EXTREMAMENTE VULNERÁVEL{RESET}")
            print(f"► Recomendação: Implementar urgentemente os cabeçalhos de segurança básicos.")
        elif seguros_encontrados < total_testes / 2:
            print(f"► Conclusão: {AMARELO}PROTEÇÕES BÁSICAS, COM VULNERABILIDADES{RESET}")
            print(f"► Recomendação: Implementar os cabeçalhos de segurança ausentes.")
        else:
            print(f"► Conclusão: {VERDE}BOA COBERTURA DE PROTEÇÕES{RESET}")
            print(f"► Recomendação: Verificar os poucos cabeçalhos ausentes para aumentar a segurança.")
        
        print(separador)
        print()
    
    return output.getvalue()

def ler_dominios_do_arquivo(arquivo):
    """
    Lê uma lista de domínios de um arquivo de texto.
    """
    with open(arquivo, 'r') as f:
        # Remove espaços em branco e linhas vazias
        dominios = [linha.strip() for linha in f if linha.strip()]
    return dominios

def processar_dominios_em_lote(arquivo_entrada, arquivo_saida):
    """
    Processa múltiplos domínios de um arquivo e salva os resultados em outro arquivo.
    """
    dominios = ler_dominios_do_arquivo(arquivo_entrada)
    
    if not dominios:
        print(f"O arquivo {arquivo_entrada} está vazio ou não contém domínios válidos.")
        return
    
    total_dominios = len(dominios)
    print(f"Processando {total_dominios} domínios...")
    
    # Criar arquivo de índice para fácil navegação
    with open(arquivo_saida, 'w') as f:
        # Cabeçalho do arquivo
        f.write("="*80 + "\n")
        f.write("RELATÓRIO DE SEGURANÇA HTTP - MÚLTIPLOS DOMÍNIOS\n")
        f.write(f"Data/Hora: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total de domínios analisados: {total_dominios}\n")
        f.write("="*80 + "\n\n")
        
        # Índice de domínios
        f.write("ÍNDICE DE DOMÍNIOS ANALISADOS\n")
        f.write("-"*40 + "\n")
        for i, dominio in enumerate(dominios, 1):
            f.write(f"{i}. {dominio}\n")
        f.write("\n" + "="*80 + "\n\n")
        
        # Análises detalhadas
        for i, dominio in enumerate(dominios, 1):
            print(f"Analisando domínio {i}/{total_dominios}: {dominio}")
            # Passamos para_arquivo=True para remover cores ANSI
            resultado = analisar_seguranca_http(dominio, para_arquivo=True)
            f.write(resultado)
    
    print(f"Análise concluída. Resultados salvos em {arquivo_saida}")

if __name__ == "__main__":
    if len(sys.argv) == 2:
        # Modo de análise de domínio único
        dominio = sys.argv[1]
        resultado = analisar_seguranca_http(dominio)
        print(resultado)
    elif len(sys.argv) == 4 and sys.argv[1] == "--batch":
        # Modo de processamento em lote
        arquivo_entrada = sys.argv[2]
        arquivo_saida = sys.argv[3]
        processar_dominios_em_lote(arquivo_entrada, arquivo_saida)
    else:
        print("Uso:")
        print("  Para verificar um único domínio:")
        print("    python3 curlvul.py dominio_a_ser_verificado")
        print("  Para verificar uma lista de domínios de um arquivo:")
        print("    python3 curlvul.py --batch arquivo_dominios.txt arquivo_saida.txt")
        sys.exit(1)