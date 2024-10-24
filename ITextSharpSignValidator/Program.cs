using System;
using System.IO;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.X509;
using System.Collections.Generic;

namespace ITextSharpSignValidator
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Please provide the path to the input PDF file as a command-line argument.");
                return;
            }

            // Get the input PDF file path from the command-line arguments
            string inputPdfPath = args[0];

            if (!File.Exists(inputPdfPath))
            {
                Console.WriteLine("The file does not exist: " + inputPdfPath);
                return;
            }

            // Path to the output text file
            string outputFilePath = Path.Combine(Path.GetDirectoryName(inputPdfPath), "output.txt");

            using (StreamWriter outputFile = new StreamWriter(outputFilePath))
            {
                try
                {
                    PdfDocument pdfDoc = new PdfDocument(new PdfReader(inputPdfPath));
                    SignatureUtil signUtil = new SignatureUtil(pdfDoc); // Use SignatureUtil to handle signatures

                    IList<string> signatureNames = signUtil.GetSignatureNames();

                    if (signatureNames.Count == 0)
                    {
                        outputFile.WriteLine("No digital signature found.");
                        Console.WriteLine("No digital signature found.");
                    }
                    else
                    {
                        foreach (string name in signatureNames)
                        {
                            outputFile.WriteLine("Signature Name: " + name);
                            Console.WriteLine("Signature Name: " + name);

                            PdfPKCS7 pkcs7 = signUtil.ReadSignatureData(name); // Get signature details
                            bool isSignatureValid = pkcs7.VerifySignatureIntegrityAndAuthenticity();
                            outputFile.WriteLine("Signature is valid: " + isSignatureValid);
                            Console.WriteLine("Signature is valid: " + isSignatureValid);

                            // Getting certificates used for signing
                            IList<X509Certificate> certs = pkcs7.GetSignCertificateChain();
                            foreach (var cert in certs)
                            {
                                outputFile.WriteLine("Signer Certificate: " + cert.SubjectDN);
                                Console.WriteLine("Signer Certificate: " + cert.SubjectDN);
                                outputFile.WriteLine("Valid From: " + cert.NotBefore);
                                Console.WriteLine("Valid From: " + cert.NotBefore);
                                outputFile.WriteLine("Valid To: " + cert.NotAfter);
                                Console.WriteLine("Valid To: " + cert.NotAfter);
                            }

                            outputFile.WriteLine("Signature covers whole document: " + pkcs7.IsTsp());
                            Console.WriteLine("Signature covers whole document: " + pkcs7.IsTsp());
                        }
                    }

                    pdfDoc.Close();
                }
                catch (Exception ex)
                {
                    outputFile.WriteLine("Error occurred: " + ex.Message);
                    Console.WriteLine("Error occurred: " + ex.Message);
                }
            }

            Console.WriteLine("Process completed. Check the output file at: " + outputFilePath);
        }
    }
}
