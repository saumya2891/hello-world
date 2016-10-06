#!perl -w

#C:\Users\jcole\Documents\Clients\TriHealth\temp\dev\lmsecparser>perl  lmparserv2.pl rawdata.txt >parse.log 2>&1

use strict;
use Data::Dumper;

my $USAGE = <<EOF;

perl $0 filename

where filename is the output from a specific db query.  See POD for details



EOF

die $USAGE unless (@ARGV) == 1;


my ($Role,$DataArea,$SecurityClass,$SecurableObject,$SecurableObjectName,$Fields,$AccessRights,$AccessibleActions,$Condition);

my $lpl;
my $excludes;
my $repeatflag;
my $recState = 0;
#state 0 = uninitialized
#state 1 = new secclass or role
#state 2 = objectType
#state 3 = lpl

open (INFILE,"<",$ARGV[0]) or die "Error - could not open $ARGV[0] for reading, $!\n";

my $outfile = "lmsecurity_" . &dateStamp . ".txt";

open (OUTFILE,">",$outfile) or die "Error - could not open $outfile for writing, $!\n";

my $line;
$repeatflag=0;
while ($line = <INFILE>) {
   chomp $line;
   if ($line =~ m/~~/) {
      $recState = 1;
      &newState1($line);
   } elsif ($recState >= 1 && $line =~ m/ BusinessClass$| WebApp$| MenuItem$| Menu$| Module$| Type$| DataArea$| BusinessTask$| KeyField$/) {
      $recState = 2;
      &newState2($line);
   } elsif ( $recState==3 && $line =~ m/is accessible|is not accessible/) {
      print "\nTrue\n";
      $recState = 4;
      &state4($line);
   }  elsif ( $recState==6 && $line =~ m/is accessible|is not accessible/) {
      print "\nTruerrrr\n";
     # $recState = 4;
     # &state4($line);
     &state12($line);
   } elsif ($recState == 3 && $line !~ m/is accessible|is not accessible/) {
      # processing Field exclusions
      &state3($line);
   } elsif ($recState == 5) {
      &state5($line);
   } elsif ($recState == 6) {
      &state6($line);
   } elsif ($recState == 10) {
      &state10($line);
   } elsif ($recState == 11) {
      &state11($line);
   }

}
close(INFILE);
&doWriteRec;
close(OUTFILE);
exit;

sub state12($)
{
  #print $Role,$DataArea,$SecurityClass,$SecurableObject,$SecurableObjectName,$AccessRights,$AccessibleActions,$Condition;
  &doWriteRec;
  $recState = 4;
  &state4($line);

}
sub state11($) {
   my $l = shift;
   $l = &trim($l);

   if ($l =~ m/for /) {
      $l =~ s/\s*for\s+//;
      $AccessibleActions = $l; 
   } elsif ($l =~ m/excluding/) {
      $AccessibleActions .= " except";
   } elsif ($l =~ m/^\s*when|^\s*uncondition/) {
      $recState = 6;
      &state6($l);
   } else {
      $AccessibleActions .= &trim($l);
   }
}


sub state10($) {
   my $l = shift;
   $l = &trim($l);
   if ($l =~ m/to all ontology/) {
      $Fields = "All ontology";
      $AccessRights = "Grants Access";
   }
   $recState = 11;
}

sub state6($) {
   my $l = shift;
   $l = &trim($l);
   if (! $l) {
      return;
   }
   $l =~ s/^\s*when\s+(.+)$/$1/;
   $l =~ s/^\s*unconditionally\s*$/Unconditionally/;
   $Condition = &trim($l); 
}


sub state5($) {
   my $l = shift;
   $l = &trim($l);
   $l =~ s/^\s*for //;
   $AccessibleActions = &trim($l);
   $recState = 6;
}


sub state4($) {
   my $l = shift;
   $l = &trim($l);
   if ($l =~ m/is not accessible/) {
      # negate the exceptions so that we speak in the affirmative
      if ($excludes) {
         $excludes =~ s/excluding/No fields except/;
         $Fields = $excludes;
         $AccessRights = "is accessible";
      }else {
         $AccessRights = $l;
      } 
    } else {
         $AccessRights = $l;
       ##  print $AccessRights;
    }
   $recState = 5;
}


sub state3($) {
   my $l = shift;
   $l = &trim($l);
   if ($l =~ m/excluding/) {
      $excludes = $l;
   } elsif ($excludes) {
      $excludes .= " $l";
   } elsif ($l =~ m/grants/) {
      $recState = 10;
   }
}


sub newState2($) {
   my $l = shift;
   my @words = split('\s+',&trim($l));
   my $checkObjType = &trim(pop @words);  # last word on line
   my $checkObjName = &trim(pop @words);  # next to last word on line
   if ($checkObjType eq "Menu") {
      if (scalar(@words) == 3 && &trim($words[1]) eq "MenuItem") {
         $checkObjType = "MenuItem";
         $checkObjName = $checkObjName . ':' . &trim($words[0]);
      }
   } elsif (scalar(@words) == 3 && &trim($words[1]) eq "Fields") {
         $Fields = "All Fields";
   }
   

   if ($SecurableObjectName && $checkObjName ne $SecurableObjectName) {
      # new securable object
      &doWriteRec();
      &initVars;
   } 
   $SecurableObjectName = $checkObjName;
   $SecurableObject = $checkObjType;
   undef $excludes;
   
   # Process the stanza related to the objectType - ovewriting previous actions, etc.
   $recState = 3;
   
}


sub newState1($) {
   my $l = shift;

   if (! $Role) {
      # if no data yet, then add headers to file
      $Role = "Role";
      $DataArea = "Data Area";
      $SecurityClass = "Security Class";
      $SecurableObject = "Securable Object";
      $SecurableObjectName = "Securable Object Name";
      $Fields = "Field(s)";
      $AccessRights = "Access Rights";
      $AccessibleActions = "Accessible Action(s)";
      $Condition = "Condition(s)";
   }
   
      ## debugging
##     print Dumper $Role,$DataArea,$SecurityClass,$SecurableObject,$SecurableObjectName,$Fields,$AccessRights,$AccessibleActions,$Condition;
      ## end debugging
      &doWriteRec();
      &initVars;
   # now get the new data started
   ($Role,$SecurityClass,$DataArea,$lpl) = split('~~',$l);
   $Role = &trim($Role);
   $DataArea = &trim($DataArea);
   $SecurityClass = &trim($SecurityClass);
   $lpl = &trim($lpl);
}




sub initVars() {
   undef $SecurableObject;
   undef $SecurableObjectName;
   undef $Fields;
   undef $AccessRights;
   undef $AccessibleActions;
   undef $Condition;
   undef $excludes;
}

sub trim($) {
   
   my $l = shift;
   if ($l) {
      $l =~ s/^\s+|\s+$//g;   
   }
   return $l;
}


sub doWriteRec() {
   if (! $Fields) {
      $Fields = '';
   }
   if (! $AccessRights && ! $AccessibleActions && ! $Condition ) {
   # print "Nothing prints in output\n";
      return;
   }

   print OUTFILE $Role . '|' .
                 $DataArea . '|' .
                 $SecurityClass . '|' .
                 $SecurableObject . '|' .
                 $SecurableObjectName . '|' .
                 $Fields . '|' .
                 $AccessRights . '|' .
                 $AccessibleActions . '|' .
                 $Condition . "\n";
}

sub dateStamp {
   my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
    my $nice_timestamp = sprintf ( "%04d%02d%02d",
                                   $year+1900,$mon+1,$mday);
    return $nice_timestamp;
}

=pod

=head1 NAME

=over 12

lmsecparser.pl

=back

=head1 VERSION

    version 1.0

=head1 SYNOPSIS

   USAGE:  perl $0 filename

   Filename is the output from a sql query below.
   This script processes the SQL output and creates a pip-delimited file to be imported into Excel and then turned into a Pivot table.

=head2 Example command-line:

=over 12

=item C<perl lmsecparser.pl rawdata.txt>

=back

=head1 DESCRIPTION

This script processes output from the following sql statement (adjusted to a specific environment) and turns the lpl into digestible data.
To use the file, first modify as appropriate and then run this sql to generate the raw data input to this process as a plain-text file.

=over 8

SELECT DISTINCT c.[ROLE], '~~' as x, c.SECURITYCLASS, '~~' as y, c.DATAAREA, '~~' as z, LPL
FROM [LTMDEV].[LMLTM].SECURITYCLASS a,
      [LTMDEV].[LMLTM].[S$SECCL] b,
      LMCMGEN.LMGEN.ROLESECURITYCLASS c
WHERE a.UNIQUEID = b.UNIQUEID 
  AND a.SECURITYCLASS = c.SECURITYCLASS
  AND c.DATAAREA = 'LTMDEV';

=back

The ~~ delimiters are critical and no other delimiters should be included in a row.
The records should be line-delimited (one record per line) LPL will violate this, which is expected.

=head2 Post Processing

This script produces a pipe-delimited output file labeled 'lmsecurity_yyyymmdd.txt'
Open a new Excel workbook.  On the data tab, import Text.
Choose delimited file format, and then select other and enter the '|' character as the delimiter.
This will create the raw data needed.  

Next click anywhere in the data and from the Insert menu, select Pivot Table.
Format the data as desired in the pivot.
One recommendation is:
Row Fields:   Security Class, Securable Object, Securable Object Name, Fields, Accessibility, Conditions
Values:  COUNT-OF Access Rights
Column Fields:  Roles

In the Analysis, remove grand and sub-totals
In the row field settings, show as classic mode.

=head1 CAVEAT EMPTOR

I don't know   LPL.  This work was based upon pre-existing work by Rob Flannery and perhaps others.
I may have misinterpreted things.  I took liberties in how I processed what I interpreted and that may result in incorrect results.
Please verify and let me know if I did things incorrectly.

One specific example and concern.

    Access Rights

        All Fields for Actor BusinessClass
            excluding
                Actor,
                PersonName
            is not accessible
                for all actions
                unconditionally

        Actor BusinessClass
            is accessible
                for all inquiries
                unconditionally


My interpretation of the above block is:
   For the Actor Business Class.  Do not allow access to any fields except Actor and PersonName and for them only permit inquiries.

   How I get there:
   All Fields but Actor, PersonName are not accessible for any actions
   Stanza 2 modifies stanza 1 
   Actor, PersonName are accessible for Inquiries unconditionally.



=head1 DEPENDENCIES

    Output from SQL Query as given above.

=head1 BUGS AND LIMITATIONS

No bugs have been reported.

Please report any bugs or feature requests to jlcole@ciber.com

=head1 AUTHOR

Jeffrey Cole  <jlcole@ciber.com>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 Ciber Inc  L<http://www.ciber.com/>.

This module is free software.  You can redistribute it and/or
modify it under the terms of the Artistic License 2.0.

This program is distributed in the hope that it will be useful,
but without any warranty; without even the implied warranty of
merchantability or fitness for a particular purpose.

=cut

# pod2html --infile=zzipcmerge.pl --outfile=zzipcMerge.html --title="In Place Conversions"  --index

__END__

