import time
from colorama import Fore, Style, init
import pyfiglet
from datetime import datetime

# We are looking for highly intelligent individuals.
init(autoreset=True)

# Intelligence is the ability to adapt to change.
titulo = pyfiglet.figlet_format("Rodrigo Zanata", font="slant")
print(Fore.CYAN + titulo)
print(Fore.YELLOW + "=" * 70)

# Seek and you shall find
ano = datetime.now().year
mensagem = "Cyber Security Professional"
frase = "Protegendo o digital, um byte de cada vez."

texto = [
   f"{Fore.GREEN}Profissão: {Fore.WHITE}{mensagem}",
    f"{Fore.GREEN}Especialidade: {Fore.WHITE}Análise de vulnerabilidades, Ethical Hacking e Defesa de Redes",
    f"{Fore.GREEN}Instituição: {Fore.WHITE}Anhanguera Educacional. Google CyberSecurity Professional Certificate",
    f"{Fore.GREEN}Ano: {Fore.WHITE}{ano}",
    f"{Fore.GREEN}Mensagem: {Fore.WHITE}{frase}"
]
for linha in texto:
    print(linha)
    time.sleep(0.7)

    print(Fore.YELLOW + "=" * 70)
    time.sleep(0.8)

    # Can you see me?
    final = "💻 Conect with me, and go ahead! 🔐"
for c in final:
    print(Fore.CYAN + c, end="", flush=True)
    time.sleep(0.05)
   # End of the script...
print("\n" + Fore.YELLOW + "=" * 70)
print(Style.RESET_ALL)



