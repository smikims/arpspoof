#!/usr/bin/perl
$|=1;
$count = 0;
$pid = $$;
while (<>) {
       @splitted=split(/ /,$_);
       chomp $_;
       if ($_ =~ /(.*\.jpg)/i) {
               $url = $1;
               system("/usr/bin/wget", "-q", "-O","/home/mark/arp/images/$pid-$count.jpg", "$url");
               system("/usr/bin/mogrify", "-flip","/home/mark/arp/images/$pid-$count.jpg");
               print "http://127.0.0.1/images/$pid-$count.jpg\n";
       }
       elsif ($_ =~ /(.*\.gif)/i) {
               $url = $1;
               system("/usr/bin/wget", "-q", "-O","/home/mark/arp/images/$pid-$count.gif", "$url");
               system("/usr/bin/mogrify", "-flip","/home/mark/images/$pid-$count.gif");
               print "http://127.0.0.1/images/$pid-$count.gif\n";
       }
       elsif ($_ =~ /(.*\.png)/i) {
               $url = $1;
               system("/usr/bin/wget", "-q", "-O","/home/mark/arp/images/$pid-$count.png", "$url");
               system("/usr/bin/mogrify", "-flip","/home/mark/arp/images/$pid-$count.png");
               print "http://127.0.0.1/images/$pid-$count.png\n";
       }
       else {
               print "$splitted[0]\n";
       }
       $count++;
}
