QRadar Ariel Data Export


Date: November 2025
Copyright 2025 Palo Alto Networks, Inc.

Paul Vinson - dl-qradar-data-export@paloaltonetworks.com

QRadar Ariel Export Process Overview
Included with this package is a document that provides a detailed overview of the QRadar Ariel Export process for QRadar captured events, which involves extracting, transforming, and exporting QRadar Ariel records into a usable format, typically gzipped JSON files. The process leverages a combination of Bash, Perl, and Java utilities, with key components working in conjunction to ensure efficient and scalable data handling. Any required Perl or Java components are installed and provided on a QRadar host, and this process will only function on a correctly-configured QRadar host. The only external dependency is the GNU Parallel package from https://www.gnu.org/software/parallel/, which is provided for you as part of this package.

Note: This extraction/conversion process is only for events, not flows. Flow record extraction/conversion is not supported at this time.

Full complete instructions are included in the PDF file titled "QRadar Ariel Export Documentation".
