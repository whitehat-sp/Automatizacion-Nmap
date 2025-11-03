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
   sudo apt install -y git

   echo -e "\t[*]Configurando git con usuario y mail ${YELLOW}temporal${RESET}"
   git config --global user.name "Pentester_Hack"
   git config --global user.email "Penteste@gmail.com"

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
    mkdir /home/kali/Downloads/auto_nmap
    cd /home/kali/Downloads/auto_nmap
    echo -e "\n"
    echo -e "\t[*]Realizando escaner  ${YELLOW}TCP${RESET} de servicios en la maquina remota ${YELLOW}${IP_HOST}${RESET}." 
    sudo nmap -vv -T5 -sS -Pn -sV -p1-65535 -n  --script=vulscan/vulscan.nse --script-args=vulscandb=scipvuldb.csv -oA scan_tcp_host "$IP_HOST"
    echo -e "\t[*]${GREEN}DONE${RESET}"

}

#Escaner de servicios udp en maquina remota
scan_host_udp(){

    #Scanning UDP
    echo -e "\n"
    echo -e "\t[*]Realizando escaner  ${YELLOW}UDP${RESET} de servicios en la maquina remota ${YELLOW}${IP_HOST}${RESET}"  
    sudo nmap -vv -T5 -sU -Pn  -sV -p1-65535 -n --script=vulscan/vulscan.nse --script-args=vulscandb=scipvuldb.csv -oA scan_udp_host "$IP_HOST"
    echo -e "\t[*]${GREEN}DONE${RESET}"

    sleep 4
}

additional_packages(){

	search_cve=("xmlstarlet" "libxml2-utils" "exploitdb")
	for scve in "${search_cve[@]}"
	do
		if sudo dpkg -s "$scve" &>/dev/null; then
			
			echo -e "\t[*]Los paquetes para hacer el parser y busquda en searchsploit esta ${YELLOW}instalados${RESET}"
		else
			echo -e "\t[-]No se han encontrados los paquetes necesarios, se realizara su instalacion"
			apt install -y "$scve"
		fi
	done
	sleep 3
}


parse_searchsploit(){

	#Variables usadas con el contenido del scanner
	xml_file="scan_tcp_host.xml"
	script_exploit_base="searchsploit_results"

	#Comprobacion de la existencia del fichero	
	if [[ ! -f "$xml_file" ]]; then
		echo -e "\t[Error]${RED}No existe el fichero xml: ${YELLOW}${xml_file}${RESET}"
		return 1
	fi

	#Parse con xmlstarlet
	echo -e "\t[*]Usando ${YELLOW}xmlstarlet${RESET} para parsear el fichero ${YELLOW}${xml_file}${RESET}"
	echo -e "\t[+]Obteniendo el fichero ${YELLOW}vulscan_context_raw.txt${RESET}..."
	xmlstarlet sel -T -m "//host" \
      		-v "address[@addrtype='ipv4']/@addr" -o "|" \
      		-m "ports/port" -v "@portid" -o "|" \
      		-v "service/@name" -o "|" \
      		-v "service/@product" -o "|" \
      		-v "service/@version" -o "|" \
      		-v "ports/port/script[@id='vulscan']" -n \
      "$xml_file" > "vulscan_context_raw.txt"

	echo -e "Eliminacion de campos vacios en el fichero ${YELLOW}vulscan_context_raw.txt${RESET}"
	echo -e "\t[+]Obteniendo el fichero ${YELLOW}vulscan_context_raw.txt${RESET}..."
	awk -F'|' '{
    		for(i=1;i<=5;i++) if($i==""||$i==" ") $i="-";
   		 # script output (campo 6) limpiar saltos de linea multiples
    			gsub(/\n/," ",$6);
    			print $1 "|" $2 "|" $3 "|" $4 "|" $5 "|" $6
  	}' "vulscan_context_raw.txt" > "vulscan_context.txt"

	echo -e "\n"
	echo -e "[*]Mostrando contenido del fichero ${YELLOW}vulscan_context.txt${RESET}"
	cat vulscan_context.txt
	sleep 4

	#Extraccion de las CVE
	grep -Eo "CVE-[0-9]{4}-[0-9]{4,7}" "vulscan_context.txt" | sort -u > "cves.txt" || true
  	echo -e "\n[*]${GREEN}CVE detectados${RESET} por ${YELLOW}vulscan${RESET}:"
  	if [ -s "cves.txt" ]; then
    		cat "cves.txt"
  	else
   		 echo -e "\t -> Ningún CVE detectado"
  	fi


	# Asume que estás en el directorio de trabajo adecuado o usa rutas absolutas
	outbase="searchsploit_results"
	mkdir -p "$outbase"
	mkdir -p "$outbase/by_cve"
	mkdir -p "$outbase/by_service"

	echo -e "[*] Buscando las ${RED}CVE${RESET} encontradas en ${YELLOW}searchsploit${RESET}"
	if [ -s "cves.txt" ]; then
  		while IFS= read -r cve; do
    			# Limpiza las CVE (normalmente CVE-YYYY-NNNN está OK, pero por seguridad quitamos espacios)
    			safe_cve=$(echo "$cve" | tr -d '[:space:]')
    			outfile_cve="$outbase/by_cve/${safe_cve}.txt"

    			searchsploit --cve "$safe_cve" --color=never > "$outfile_cve" 2>/dev/null || true

    			if [ -s "$outfile_cve" ]; then
      				echo -e "\t[+] Resultados guardados: $outfile_cve"
    			else
      				rm -f "$outfile_cve"
      				echo -e "\t[-] No se encontraron resultados para $safe_cve en searchsploit"
    			fi
 	 	done < "cves.txt"
	else
  		echo -e "\t(archivo cves.txt vacío o no existe)"
	fi

	#Búsqueda por servicio/product/version
	echo -e "\n[*] Buscando por product+version o servicio (fallback) ..."
	if [ ! -f "vulscan_context.txt" ]; then
  		echo -e "\t[ERROR] No existe vulscan_context.txt. Salida previa del parseo requerida."
	else
  		while IFS='|' read -r ip port service product version script_out; do
    			product=${product:-"-"}
    			version=${version:-"-"}
    			service=${service:-"-"}

    			if [ "$product" != "-" ] && [ "$version" != "-" ]; then
      				query="$product $version"
    			elif [ "$product" != "-" ]; then
      				query="$product"
    			else
      				query="$service"
    			fi

    			#Limpieza de la query para hacer un parseo a searchsploit
    			query_sanitized=$(echo "$query" | sed 's/["'"'"'|<>]/ /g' | sed 's/  */ /g' | sed 's/^ //;s/ $//')

    			#Limpiando nombre de archivos
    			safe_ip=$(echo "$ip" | tr -cd 'A-Za-z0-9._-')
    			safe_port=$(echo "$port" | tr -cd 'A-Za-z0-9._-')
    			safe_service=$(echo "$service" | tr ' /' '__' | tr -cd 'A-Za-z0-9._-__')

    			outfile="$outbase/by_service/${safe_ip}_${safe_port}_${safe_service}.txt"

    			echo -e "\t -> Buscando: \"$query_sanitized\"  (host:$ip port:$port service:$service)"
    			searchsploit "$query_sanitized" --color=never > "$outfile" 2>/dev/null || true

    			if [ -s "$outfile" ]; then
      				echo -e "\t   [+] Resultados: $outfile"
    			else
      				rm -f "$outfile"
      				echo -e "\t   [-] No resultados para: $query_sanitized"
    			fi
  		done < "vulscan_context.txt"
	fi

		echo -e "\n[*] Búsqueda finalizada. Resultados en: $outbase/"
}	


additional_packages
check_ip
cve-vulscan
scan_host_tcp
scan_host_udp
parse_searchsploit
