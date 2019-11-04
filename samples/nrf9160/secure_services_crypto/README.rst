.. _secure_services:

nRF9160: Secure Services Crypto Sample
######################################

The Secure Services sample shows how to use the secure crypto services provided by :ref:`secure_partition_manager` with additional crypto support.
This firmware needs :ref:`secure_partition_manager` to also be present on the chip.

Overview
********

This sample performed selected crypto operations on dummy data sets using both CC310 HW via sercure
services and mbed TLS in pure SW for comparison.

Requirements
************

The following development board:

* nRF9160 DK board (PCA10090)

The following sample must be also be flashed (happens automatically with the default configuration):

* :ref:`secure_partition_manager`

Building and running
********************

.. |sample path| replace:: :file:`samples/nrf9160/secure_services`

.. include:: /includes/build_and_run.txt

The sample is built as a non-secure firmware image for the nrf9160_pca10090ns board.
:ref:`secure_partition_manager` will by default be automatically built and flashed together with this sample.


Dependencies
************

This sample uses the following |NCS| libraries:

* :ref:`lib_spm`
