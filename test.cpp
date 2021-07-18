#include "NanoLog.hpp"

int main()
{

  nanolog::initialize(nanolog::GuaranteedLogger(), "/home/huzixiaoshu/pro_learn/NanoLog/nanolog/", "nanolog", 1);

  for (int i = 0; i < 5; ++i)
  {
    LOG_INFO << "Sample NanoLog: " << i;
  }
  
  // Change log level at run-time.
  nanolog::set_log_level(nanolog::LogLevel::CRIT);
  LOG_WARN << "This log line will not be logged since we are at loglevel = CRIT";
  
  return 0;
}