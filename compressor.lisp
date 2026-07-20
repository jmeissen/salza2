;;;
;;; Copyright (c) 2007 Zachary Beane, All Rights Reserved
;;;
;;; Redistribution and use in source and binary forms, with or without
;;; modification, are permitted provided that the following conditions
;;; are met:
;;;
;;;   * Redistributions of source code must retain the above copyright
;;;     notice, this list of conditions and the following disclaimer.
;;;
;;;   * Redistributions in binary form must reproduce the above
;;;     copyright notice, this list of conditions and the following
;;;     disclaimer in the documentation and/or other materials
;;;     provided with the distribution.
;;;
;;; THIS SOFTWARE IS PROVIDED BY THE AUTHOR 'AS IS' AND ANY EXPRESSED
;;; OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;;; WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
;;; ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
;;; DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
;;; GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
;;; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
;;; WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;

(in-package #:salza2)

(defun make-input ()
  (make-array 65536 :element-type 'octet))

(defun make-chains ()
  (make-array 65536
              :element-type '(unsigned-byte 16)
              :initial-element 0))

(defun make-hashes ()
  (make-array +hashes-size+
              :element-type '(unsigned-byte 16)
              :initial-element 0))

(defun error-missing-callback (&rest args)
  (declare (ignore args))
  (error "No callback given for compression"))

;;; Merge input into the 64k history ring. Pending input is tracked
;;; independently of the physical 32k halves so that it can be compressed at
;;; an arbitrary packet boundary and subsequent input will not be compressed
;;; a second time.

(defun merge-input (input input-start count output output-offset
                    pending-start pending-count compress-fun)
  "Merge COUNT octets from INPUT-START of INPUT into OUTPUT.
Whenever 32k octets are pending, call COMPRESS-FUN and start a new pending
range. Return OUTPUT-OFFSET, PENDING-START, and PENDING-COUNT."
  (declare (type octet-vector input output))
  (let ((input-offset input-start))
    (loop while (plusp count)
          for copy-count = (min count
                                (- +input-limit+ pending-count)
                                (- +buffer-size+ output-offset))
          do (replace output input
                      :start1 output-offset
                      :start2 input-offset
                      :end2 (+ input-offset copy-count))
             (incf input-offset copy-count)
             (decf count copy-count)
             (incf pending-count copy-count)
             (setf output-offset
                   (logand +buffer-size-mask+ (+ output-offset copy-count)))
             (when (= pending-count +input-limit+)
               (funcall compress-fun output pending-start pending-count)
               (setf pending-start output-offset
                     pending-count 0)))
    (values output-offset pending-start pending-count)))

(defun reinitialize-bitstream-funs (compressor bitstream)
  (setf (literal-fun compressor)
        (make-huffman-writer *fixed-huffman-codes* bitstream)
        (length-fun compressor)
        (make-huffman-writer *length-codes* bitstream)
        (distance-fun compressor)
        (make-huffman-writer *distance-codes* bitstream)
        (compress-fun compressor)
        (make-compress-fun compressor)))


;;; Class & protocol

(defclass deflate-compressor ()
  ((input
    :initarg :input
    :accessor input)
   (chains
    :initarg :chains
    :accessor chains)
   (hashes
    :initarg :hashes
    :accessor hashes)
   (start
    :initarg :start
    :accessor start)
   (end
    :initarg :end
    :accessor end)
   (counter
    :initarg :counter
    :accessor counter)
   (block-open-p
    :initarg :block-open-p
    :accessor block-open-p)
   (finished-p
    :initarg :finished-p
    :accessor finished-p)
   (octet-buffer
    :initarg :octet-buffer
    :accessor octet-buffer)
   (bitstream
    :initarg :bitstream
    :accessor bitstream)
   (literal-fun
    :initarg :literal-fun
    :accessor literal-fun)
   (length-fun
    :initarg :length-fun
    :accessor length-fun)
   (distance-fun
    :initarg :distance-fun
    :accessor distance-fun)
   (byte-fun
    :initarg :byte-fun
    :accessor byte-fun)
   (compress-fun
    :initarg :compress-fun
    :accessor compress-fun))
  (:default-initargs
   :input (make-input)
   :chains (make-chains)
   :hashes (make-hashes)
   :start 0
   :end 0
   :counter 0
   :block-open-p nil
   :finished-p nil
   :bitstream (make-instance 'bitstream)
   :octet-buffer (make-octet-vector 1)))

;;; Public protocol GFs

(defgeneric start-data-format (compressor)
  (:documentation "Add any needed prologue data to the output bitstream."))

(defgeneric compress-octet (octet compressor)
  (:documentation "Add OCTET to the compressed data of COMPRESSOR."))

(defgeneric compress-octet-vector (vector compressor &key start end)
  (:documentation "Add the octets of VECTOR to the compressed
  data of COMPRESSOR."))

(defgeneric process-input (compressor input start count)
  (:documentation "Map over pending octets in INPUT and perform
  any needed processing. Called before the data is compressed. A
  subclass might use this to compute a checksum of all input
  data."))

(defgeneric finish-data-format (compressor)
  (:documentation "Add any needed epilogue data to the output bitstream."))

(defgeneric partial-flush-compression (compressor)
  (:documentation "Compress all pending input and emit enough compressed
  output for a decompressor to consume it without ending the data format or
  resetting compression history. Because compressed sizes can reveal matches
  against retained history, do not use one compression context for both
  confidential and attacker-controlled data when output sizes are observable."))

(defgeneric finish-compression (compressor)
  (:documentation "Finish the data format and flush all pending
  data in the bitstream."))

;;; Internal GFs

(defgeneric final-compress (compressor)
  (:documentation "Perform the final compression on pending input
  data in COMPRESSOR."))

(defgeneric make-compress-fun (compressor)
  (:documentation "Create a callback suitable for passing to
  MERGE-INPUT for performing incremental compression of the next
  32k octets of input."))

;;; Methods

(defmethod initialize-instance :after ((compressor deflate-compressor)
                                       &rest initargs
                                       &key
                                       literal-fun length-fun distance-fun
                                       compress-fun
                                       callback)
  (declare (ignore initargs))
  (let ((bitstream (bitstream compressor)))
    (setf (callback bitstream)
          (or callback #'error-missing-callback))
    (setf (literal-fun compressor)
          (or literal-fun (make-huffman-writer *fixed-huffman-codes*
                                               bitstream)))
    (setf (length-fun compressor)
          (or length-fun (make-huffman-writer *length-codes*
                                              bitstream)))
    (setf (distance-fun compressor)
          (or distance-fun (make-huffman-writer *distance-codes*
                                                bitstream)))
    (setf (compress-fun compressor)
          (or compress-fun (make-compress-fun compressor)))
    (start-data-format compressor)))

;;; A few methods defer to the bitstream

(defmethod (setf callback) (new-fun (compressor deflate-compressor))
  (let ((bitstream (bitstream compressor)))
    (prog1
        (setf (callback bitstream) new-fun)
      (reinitialize-bitstream-funs compressor bitstream))))

(defmethod write-bits (code size (compressor deflate-compressor))
  (write-bits code size (bitstream compressor)))

(defmethod write-octet (octet (compressor deflate-compressor))
  (write-octet octet (bitstream compressor)))

(defmethod write-octet-vector (vector (compressor deflate-compressor)
                               &key (start 0) end)
  (write-octet-vector vector (bitstream compressor)
                      :start start
                      :end end))
                               

(defun ensure-compressor-active (compressor)
  (when (finished-p compressor)
    (error "Compression has already been finished for ~S" compressor)))

(defun start-fixed-block (compressor finalp)
  (let ((bitstream (bitstream compressor)))
    (write-bits (if finalp +final-block+ +non-final-block+) 1 bitstream)
    (write-bits +fixed-tables+ 2 bitstream)
    (setf (block-open-p compressor) t)))

(defun end-fixed-block (compressor)
  (when (block-open-p compressor)
    (funcall (literal-fun compressor) 256)
    (setf (block-open-p compressor) nil)))

(defun emit-empty-fixed-block (compressor finalp)
  (start-fixed-block compressor finalp)
  (end-fixed-block compressor))

(defmethod start-data-format ((compressor deflate-compressor))
  (start-fixed-block compressor nil))

(defmethod compress-octet (octet (compressor deflate-compressor))
  (let ((vector (octet-buffer compressor)))
    (setf (aref vector 0) octet)
    (compress-octet-vector vector compressor)))

(defmethod compress-octet-vector (vector (compressor deflate-compressor)
                                  &key (start 0) end)
  (ensure-compressor-active compressor)
  (let* ((closure (compress-fun compressor))
         (end (or end (length vector)))
         (count (- end start)))
    (when (plusp count)
      (unless (block-open-p compressor)
        (start-fixed-block compressor nil))
      (multiple-value-bind (output-offset pending-start pending-count)
          (merge-input vector start count
                       (input compressor)
                       (end compressor)
                       (start compressor)
                       (counter compressor)
                       closure)
        (setf (end compressor) output-offset
              (start compressor) pending-start
              (counter compressor) pending-count)))))

(defmethod process-input ((compressor deflate-compressor) input start count)
  (update-chains input (hashes compressor) (chains compressor) start count))

(defmethod finish-data-format ((compressor deflate-compressor))
  (end-fixed-block compressor)
  (emit-empty-fixed-block compressor t))

(defmethod partial-flush-compression ((compressor deflate-compressor))
  (ensure-compressor-active compressor)
  (when (block-open-p compressor)
    (final-compress compressor)
    (end-fixed-block compressor)
    ;; RFC 4253 requires at least eight bits from the start of the current
    ;; end-of-block code to the end of the packet. For Salza2's fixed blocks,
    ;; this ten-bit empty fixed block provides the required trailing bits.
    (emit-empty-fixed-block compressor nil))
  (flush-complete-octets (bitstream compressor)))

(defmethod finish-compression ((compressor deflate-compressor))
  (unless (finished-p compressor)
    (when (block-open-p compressor)
      (final-compress compressor))
    (finish-data-format compressor)
    (flush (bitstream compressor))
    (setf (finished-p compressor) t)))

(defmethod final-compress ((compressor deflate-compressor))
  (let ((input (input compressor))
        (chains (chains compressor))
        (start (start compressor))
        (end (end compressor))
        (counter (counter compressor))
        (literal-fun (literal-fun compressor))
        (length-fun (length-fun compressor))
        (distance-fun (distance-fun compressor)))
    (when (plusp counter)
      (process-input compressor input start counter)
      (compress input chains start end
                literal-fun
                length-fun
                distance-fun)
      (setf (start compressor) end
            (counter compressor) 0))))

(defmethod make-compress-fun ((compressor deflate-compressor))
  (let ((literal-fun (literal-fun compressor))
        (length-fun (length-fun compressor))
        (distance-fun (distance-fun compressor)))
    (lambda (input start count)
      (process-input compressor input start count)
      (let ((end (+ start count)))
        (compress input (chains compressor) start (logand #xFFFF end)
                  literal-fun
                  length-fun
                  distance-fun)))))

(defmethod reset ((compressor deflate-compressor))
  (fill (chains compressor) 0)
  (fill (input compressor) 0)
  (fill (hashes compressor) 0)
  (setf (start compressor) 0
        (end compressor) 0
        (counter compressor) 0
        (block-open-p compressor) nil
        (finished-p compressor) nil)
  (reset (bitstream compressor))
  (start-data-format compressor))


(defmacro with-compressor ((var class
                                &rest initargs
                                &key &allow-other-keys)
                           &body body)
  `(let ((,var (make-instance ,class ,@initargs)))
     (multiple-value-prog1 
         (progn ,@body)
       (finish-compression ,var))))
