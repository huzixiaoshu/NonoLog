# [NonoLog_Iyengar111](https://github.com/Iyengar111/NanoLog)
* Low Latency C++11 Logging Library. 
* It's fast. Very fast. See [Latency benchmark](#latency-benchmark-of-guaranteed-logger)
* NanoLog only uses standard headers so it should work with any C++11 compliant compiler.
* Supports typical logger features namely multiple log levels, log file rolling and asynchronous writing to file.

# Design highlights
* Zero copying of string literals.
* Lazy conversion of integers and doubles to ascii. 
* No heap memory allocation for log lines representable in less than ~256 bytes.
* Minimalistic header includes. Avoids common pattern of header only library. Helps in compilation times of projects.

# Guaranteed and Non Guaranteed logging
* Nanolog supports Guaranteed logging i.e. log messages are never dropped even at extreme logging rates.
* Nanolog also supports Non Guaranteed logging. Uses a ring buffer to hold log lines. In case of extreme logging rate when the ring gets full (i.e. the consumer thread cannot pop items fast enough), the previous log line in the slot will be dropped. Does not block producer even if the ring buffer is full.

# Usage
```c++
#include "NanoLog.hpp"

int main()
{
  // Ensure initialize is called once prior to logging.
  // This will create log files like /tmp/nanolog1.txt, /tmp/nanolog2.txt etc.
  // Log will roll to the next file after every 1MB.
  // This will initialize the guaranteed logger.
  nanolog::initialize(nanolog::GuaranteedLogger(), "/tmp/", "nanolog", 1);
  
  // Or if you want to use the non guaranteed logger -
  // ring_buffer_size_mb - LogLines are pushed into a mpsc ring buffer whose size
  // is determined by this parameter. Since each LogLine is 256 bytes,
  // ring_buffer_size = ring_buffer_size_mb * 1024 * 1024 / 256
  // In this example ring_buffer_size_mb = 3.
  // nanolog::initialize(nanolog::NonGuaranteedLogger(3), "/tmp/", "nanolog", 1);
  
  for (int i = 0; i < 5; ++i)
  {
    LOG_INFO << "Sample NanoLog: " << i;
  }
  
  // Change log level at run-time.
  nanolog::set_log_level(nanolog::LogLevel::CRIT);
  LOG_WARN << "This log line will not be logged since we are at loglevel = CRIT";
  
  return 0;
}
