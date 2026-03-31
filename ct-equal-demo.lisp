;;; Standalone demonstration of the PR #4 constant-time-equal bug.

(declaim (optimize (speed 3) (safety 1) (debug 3)))

(defun buggy-constant-time-equal (a b)
  "Copy of the PR #4 constant-time-equal implementation."
  (declare (type (simple-array (unsigned-byte 8) (*)) a b)
           (optimize speed))
  (let ((len-a (length a))
        (len-b (length b)))
    (declare (type fixnum len-a len-b))
    ;; BUG: truncates the length XOR to 8 bits.
    (let ((diff (logand #xff (logxor len-a len-b))))
      (declare (type (unsigned-byte 8) diff))
      (loop for i fixnum from 0 below (min len-a len-b)
            do (setf diff (logior diff (logxor (aref a i) (aref b i)))))
      (zerop diff))))

(defun fixed-constant-time-equal (a b)
  "Same logic without the 8-bit truncation bug."
  (declare (type (simple-array (unsigned-byte 8) (*)) a b)
           (optimize speed))
  (let ((len-a (length a))
        (len-b (length b)))
    (declare (type fixnum len-a len-b))
    (let ((diff (logxor len-a len-b)))
      (loop for i fixnum from 0 below (min len-a len-b)
            do (setf diff (logior diff (logxor (aref a i) (aref b i)))))
      (zerop diff))))

(defun octets (len &optional (value 0))
  (make-array len :element-type '(unsigned-byte 8) :initial-element value))

(defun show-case (name a b)
  (format t "~A~%" name)
  (format t "  lengths: ~D vs ~D~%" (length a) (length b))
  (format t "  buggy result: ~S~%" (buggy-constant-time-equal a b))
  (format t "  fixed result: ~S~%" (fixed-constant-time-equal a b))
  (format t "~%"))

(defun main ()
  ;; False positive: lengths differ by 256, shared prefix is equal, loop covers
  ;; only the common prefix, and the truncated length XOR becomes zero.
  (let ((a (octets 256 0))
        (b (octets 0 0))
        (c (octets 257 0))
        (d (octets 1 0)))
    (show-case "Case 1: 256-byte vector vs empty vector" a b)
    (show-case "Case 2: 257-byte vector vs 1-byte vector" c d)))

(main)
