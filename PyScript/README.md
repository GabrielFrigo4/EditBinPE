# EditPE and GpuPE (Python Script)
It is a CLI application that has the function of looking at and editing the headers of PE32 and PE32+ files

It uses 'pefile' and 'lief' python modules

# How to Use
To enable-gpu use: gpupe infile.exe outfile.exe
or
To enable-gpu use: editpe infile.exe outfile.exe "NvOptimusEnablement,1" "AmdPowerXpressRequestHighPerformance,1"