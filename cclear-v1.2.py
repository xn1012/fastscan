import os
import multiprocessing
dir0 = os.getcwd()
sub_num = multiprocessing.cpu_count()

def main(): 
    file = raw_input("input the domain file name:")
    dir1 = dir0 + '/out2/' 
    str1 = dir1 + file + '_open'

    with open(str1, 'w') as results1:
        for i in xrange(sub_num):
            try:
                with open(dir1 + file + '_IPs_' + str(i) + '_open','r') as f1:
                    content1 = f1.read()
                    results1.write(content1)
            except Exception as e:
                continue
    Clear_helper(file)


def Clear_helper(file):
    str0 = dir0 + '/input/' + file 
    str00 = dir0 + '/input/' + file + '_IPs'
    dir1 = dir0 + '/out2/'

    try:
        os.remove(str00)
    except:
        pass

    for i in xrange(sub_num):
        subfile = str00 + '_' + str(i)
        str1 = dir1 + file + '_IPs_' + str(i) + '_open'

        try:
            os.remove(str1)
        except:
            pass
        try:
            os.remove(subfile)
        except:
            pass

    print("\nclear work have done!")



if __name__ == '__main__':
    main()