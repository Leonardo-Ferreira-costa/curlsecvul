# curlsecvul
Script em Python que utiliza o comando curl para realizar um check list em um dóminio e verificar o que pode estar vulnerável.


🛠️ **Requisitos:** Python


🚀 **Uso:** python3 curlvul.py dominio_a_ser_verificado



Ele realiza 13 verificações:

**status_seguro:** Refere-se à verificação se uma conexão é segura (HTTPS) e retorna o status do protocolo.

**location_seguro:** Diretiva que manipula redirecionamentos, importante para garantir que os usuários sejam enviados para versões seguras de páginas.

**csp_seguro (Content Security Policy):** Política de Segurança de Conteúdo, define quais fontes de conteúdo (scripts, estilos, etc.) são permitidas em uma página, ajudando a prevenir ataques de script entre sites (XSS).

**hsts_seguro (HTTP Strict Transport Security):** Força os navegadores a usar HTTPS para se conectar ao servidor, evitando ataques de "man-in-the-middle".

**xss_seguro (Cross-Site Scripting):** Medidas para prevenir ataques XSS, que ocorrem quando código malicioso é injetado em páginas web.

**content_type_seguro:** Garante que o tipo de conteúdo (MIME type) da resposta do servidor seja corretamente especificado, prevenindo que o navegador interprete o conteúdo de forma inadequada.

**referrer_policy_seguro (Política de Referenciador):** Controla quais informações de referenciador são enviadas em requisições HTTP, protegendo a privacidade do usuário.

**permissions_policy_seguro (Política de Permissões):** Permite que um site habilite ou desabilite o uso de certos recursos do navegador (como geolocalização, câmera, etc.), oferecendo mais controle sobre o que o site pode fazer.

**clear_site_data_seguro:** Limpa dados do navegador associados ao site (cookies, armazenamento local, etc.), útil para garantir que os usuários tenham uma experiência limpa ao sair de um site, ou por motivos de segurança.

**coop_seguro (Cross-Origin Opener Policy):** Isola o contexto de navegação de um documento para prevenir que ele seja manipulado por sites maliciosos.

**corp_seguro (Cross-Origin Resource Policy):** Permite que os servidores declarem quem pode carregar seus recursos, prevenindo o compartilhamento de recursos entre origens de forma não intencional.

**coep_seguro (Cross-Origin Embedder Policy):** Impede que um documento carregue recursos de outras origens se eles não derem permissão, trabalhando em conjunto com o COOP e CORP para fortalecer o isolamento de segurança.

![image](https://github.com/user-attachments/assets/ad446c7f-3dcd-4a62-bc32-b39f03b80909)

