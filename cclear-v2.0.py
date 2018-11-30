import os
import multiprocessing

sub_num = multiprocessing.cpu_count()
dir0 = os.getcwd()
dir1 = dir0 + '/out2/' 


def main(): 
    file = raw_input("input the domain file name:")
    str1 = dir1 + file + '_open'

    with open(str1, 'w') as f4:
        for i in xrange(sub_num):
            sfile = file + '_' + str(i) + '_IPsss'
            str2 = dir1 + sfile + '_open'
            try:
                with open(str2, 'r') as fsub:
                    content = fsub.read()
                    f4.write(content)
            except Exception as e:
                pass
    Clear_helper(file)


def Clear_helper(file):
    str0 = dir0 + '/input/' + file 
    dir1 = dir0 + '/out2/'

    for i in xrange(sub_num):
        subfile1 = str0 + '_' + str(i)
        subfile2 = subfile1 + '_IPs'
        str1 = dir1 + file + '_' + str(i)+ '_IPs_open'
        try:
            os.remove(str1)
        except:
            pass
        try:
            os.remove(subfile1)
        except:
            pass
        try:
            os.remove(subfile2)
            for j in xrange(sub_num):
                os.remove(subfile2 + '_' + str(j))
        except:
            pass

    print("\nclear work have done!")

if __name__ == '__main__':
    main()
