### Shorthand options

all: ps

pg: pap.ps.gz

bib: bibtex

paper = paper
#### Longhand options

dvi: force
	latex -shell-escape -halt-on-error  $(paper).tex 
	#cp $(paper).bib out
	#cd out;	bibtex $(paper); cd ../
	bibtex $(paper)
	latex -shell-escape -halt-on-error  $(paper).tex  
	latex -shell-escape -halt-on-error  $(paper).tex  

ps: dvi *.tex
	dvips -Ppdf -G0 -o $(paper).ps -t letter $(paper).dvi
	ps2pdf -dPDFSETTINGS=/prepress -dEmbedAllFonts=true $(paper).ps ./$(paper).pdf   >/dev/null
	rm $(paper).aux  $(paper).log $(paper).out $(paper).ps $(paper).blg $(paper).bbl $(paper).dvi

bibtex:	force
	bibtex $(paper)

xdvi:  dvi force
	xdvi -s 3 $(paper) &

clean: force
	rm $(paper).aux  $(paper).log $(paper).out $(paper).ps $(paper).blg $(paper).bbl $(paper).dvi $(paper).pdf

force:
	
