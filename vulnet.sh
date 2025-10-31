#!/bin/bash
#Orquestation Bash

#Color
#-----/
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
RESET='\033[0m'

clear
echo -e "\n"
echo -e "\t--------------------------------------------"
echo -e "\t${RED}   _   ____  ____   _  ____________  ${RESET}"
echo -e "\t${RED}  | | / / / / / /  / |/ / __/_  __/  ${RESET}"
echo -e "\t${RED}  | |/ / /_/ / /__/    / _/  / /     ${RESET}"
echo -e "\t${RED}  |___/\____/____/_/|_/___/ /_/   by:Fausto Diaz${RESET}"
echo -e "\t-------------------------------------------"

#Data-Host
echo -e "\n"
read -p "Escribe la ip: " IP_HOST
echo -e "\n"

#Funcion para validacion direccionamiento ip
check_ip(){
 	
    #Validacion de variable 'IP_HOST'
    if [[ -z "${IP_HOST}" ]]; then
	    echo -e "\t[${RED}Error${RESET}] No has introducido una IP. Cancelando operacion.."
	    exit 1
    fi 

    if [[ $IP_HOST =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  
        # Ahora verificamos que cada octeto esté entre 0 y 255
        IFS='.' read -r o1 o2 o3 o4 <<< "$IP_HOST"
        if (( o1 <= 255 && o2 <= 255 && o3 <= 255 && o4 <= 255 )); then 
             echo -e "\t -> ${GREEN}IP válida${RESET}: ${YELLOW}$IP_HOST${RESET}"
        else
             echo -e "\t -> ${RED}Error${RESET}: alguno de los octetos está fuera del rango 0–255"
             exit 1
        fi
   else
        echo -e "\t -> ${RED}Error${RESET}: formato de IP no válido"
        exit 1
   fi
}

cve-vulscan(){

   #Instalado git
   echo -e "\t[*]Instalando ${YELLOW}git${RESET} en el equipo.."
   apt install git

   echo -e "\t[*]Configurando git con usuario y mail ${YELLOW}temporal${RESET}"
   git config --global user.name "Pentester_Hack"
   git config --global user.mail "Penteste@gmail.com"

   #Descarga de repositorio
   if [[ -d "/usr/share/nmap/scripts/vulscan" && -f "/usr/share/nmap/scripts/vulscan/vulscan.nse" ]]; then
        echo "Ya tienes vulscan"
   else
      sudo git clone --depth 1 https://github.com/scipag/vulscan.git /usr/share/nmap/scripts/vulscan
   fi   
   
   #Eliminacion configuracion git temporal
   echo -e "\t[-]${YELLOW}Eliminando${RESET} la configuracion temporal de git.."
   rm -rf ~/.gitconfig
   echo -e "\t[*]${GREEN}OK!!"
}

#Escaner de servicios tcp en maquina remota
scan_host_tcp(){
    
    #Scannint TCP
    echo -e "\n"
    echo -e "\t[*]Realizando escaner  ${YELLOW}TCP${RESET} de servicios en la maquina remota ${YELLOW}${IP_HOST}${RESET}." 
    sudo nmap -vv -T5 -sS -Pn -sV -p1-65535 -n  --script=vulscan --script-args=vulscandb=scipvuldb.csv -oN scan_tcp_host.txt "$IP_HOST"
    echo -e "\t[*]${GREEN}DONE${RESET}"

}

#Escaner de servicios udp en maquina remota
scan_host_udp(){

    #Scanning UDP
    echo -e "\n"
    echo -e "\t[*]Realizando escaner  ${YELLOW}UDP${RESET} de servicios en la maquina remota ${YELLOW}${IP_HOST}${RESET}"  
    sudo nmap -vv -T5 -sU -Pn  -sV -p1-65535 -n --script=vulscan --script-args=vulscandb=scipvuldb.csv -oN scan_udp_host.txt "$IP_HOST"
    echo -e "\t[*]${GREEN}DONE${RESET}"

    sleep 4
}

clean_file_service(){

   #Limpieza fichero servicios TCP
   echo -e "\t[*]${YELLOW}Limpiando${RESET} contenido del fichero para servicios de ${GREEN}TCP${RESET}"
   OKcat scan_tcp_host.txt | tr -s ' ' | cut -d' ' -f1 | cut -d'/' -f1 > scan_tcp_host_cl.txt
   rm -rf scan_tcp_host.txt
   echo -e "\t[*]${GREEN}DONE${RESET}"
   echo -e "Verificando puertos obtenidos"
   cat scan_tcp_host_cl.txt

   #Limpieza ficheros servicios UDP
   echo -e "\t[*]${YELLOW}Limpiando${RESET} contenido del fichero para servicios de ${GREEN}UDP${RESET}"
   cat scan_udp_host.txt | tr -s ' ' | cut -d' ' -f1 | cut -d'/' -f1 > scan_udp_host_cl.txt
   rm -rf scan_udp_host.txt
   echo -e "\t[*]${GREEN}DONE${RESET}"
   cat scan_udo_host_cl.txt
   sleep 3

}

cve-vulscan
check_ip
scan_host_tcp
scan_host_udp
clean_file_service
                                
