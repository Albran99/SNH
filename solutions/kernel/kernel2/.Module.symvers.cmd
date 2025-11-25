cmd_/home/studenti/kernel/Module.symvers :=  sed 's/ko$$/o/'  /home/studenti/kernel/modules.order | scripts/mod/modpost -m     -o /home/studenti/kernel/Module.symvers -e -i Module.symvers -T - 
