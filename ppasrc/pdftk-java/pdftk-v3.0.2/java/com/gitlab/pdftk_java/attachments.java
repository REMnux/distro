/*
 *
 *   This file is part of the pdftk port to java
 *
 *   Copyright (c) Marc Vinyals 2017-2018
 *
 *   The program is a java port of PDFtk, the PDF Toolkit
 *   Copyright (c) 2003-2013 Steward and Lee, LLC
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   The program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package com.gitlab.pdftk_java;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import pdftk.com.lowagie.text.pdf.PdfDictionary;
import pdftk.com.lowagie.text.pdf.PdfName;
import pdftk.com.lowagie.text.pdf.PdfReader;
import pdftk.com.lowagie.text.pdf.PdfStream;
import pdftk.com.lowagie.text.pdf.PdfString;
import pdftk.com.lowagie.text.pdf.PRStream;

class attachments {
static String
  drop_path( String ss )
{
  int loc = ss.lastIndexOf( File.separatorChar );
  if( loc != -1 && loc!= ss.length()- 1 ) {
    return ss.substring( loc+ 1 );
  }
  return ss;
}

static String
normalize_pathname( String output_pathname )
{
  if( output_pathname== "PROMPT" ) {
    output_pathname = pdftk.prompt_for_filename( "Please enter the directory where you want attachments unpacked:" );
  }
  if( output_pathname.lastIndexOf( File.separatorChar )== output_pathname.length()- 1 ) {
    return output_pathname;
  }
  else{ // add delim to end
    return output_pathname+ File.separatorChar;
  }
}

static void
unpack_file( PdfReader input_reader_p,
             PdfDictionary filespec_p,
             String output_pathname,
             boolean ask_about_warnings_b )
{
  if( filespec_p != null && filespec_p.isDictionary() ) {

    PdfName type_p= (PdfName)
      input_reader_p.getPdfObject( filespec_p.get( PdfName.TYPE ) );
    if( type_p != null && type_p.isName() && 
        ( type_p.compareTo( PdfName.FILESPEC )== 0 ||
          type_p.compareTo( PdfName.F )== 0 ) )
      {
        PdfDictionary ef_p= (PdfDictionary)
          input_reader_p.getPdfObject( filespec_p.get( PdfName.EF ) );
        if( ef_p != null && ef_p.isDictionary() ) {

          // UF introduced in PDF 1.7
          PdfString fn_p= (PdfString)
            input_reader_p.getPdfObject( filespec_p.get( PdfName.UF ) );
          if( fn_p == null ) { // try the F key
            fn_p= (PdfString)
            input_reader_p.getPdfObject( filespec_p.get( PdfName.F ) );
          }

          if( fn_p != null && fn_p.isString() ) {

            // patch by Johann Felix Soden <johfel@gmx.de>
            // patch tweaked by Sid Steward:
            // toString() doesn't ensure conversion from internal encoding (e.g., Y+diaeresis)
            String fn_str = fn_p.toUnicodeString();
            String fn= drop_path( fn_str );

            // did the user supply a path?
            if( !output_pathname.isEmpty() ) { // prepend it
              fn= output_pathname+ fn; // output_pathname has been normalized, already
            }
                      
            // assuming that F key is used to store the data, and not DOS, Mac, or Unix
            PdfStream f_p= (PdfStream)
              input_reader_p.getPdfObject( ef_p.get( PdfName.F ) );
            if( f_p != null && f_p.isStream() ) {

              try {
                byte[] bytes_p= input_reader_p.getStreamBytes( (PRStream)f_p );

                if( ask_about_warnings_b ) {
                  // test for existing file by this name
                  if ( pdftk.file_exists( fn ) ) {
                    if ( !pdftk.confirm_overwrite( fn ) ) {
                      System.out.println( "   Skipping: " + fn );
                      return; // <--- return
                    }
                  }
                }
                FileOutputStream ofs = new FileOutputStream( fn );
                ofs.write( bytes_p );
                ofs.close();
              }
              catch ( IOException e ) { // error
                System.err.println( "Error: unable to create the file:" );
                System.err.println( "   " + fn );
                System.err.println( "   Skipping.");
              }
            }
          }
        }
      }
  }
}
  
}
