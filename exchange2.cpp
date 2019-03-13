#include <iostream>
#include <string>
#include <vector>
#include <list>
#include <set>
#include <map>
#include <queue>
#include <functional>
#include <algorithm>
#include <mutex>
#include <thread>
#include <condition_variable>

#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

template<class T> void dot(const T & t) { std::cout << t << std::flush; }

std::string timestamp_2_string(uint32_t stamp)
{
  struct tm tformat = {0};
  time_t tt(stamp);
  localtime_r(&tt, &tformat); 
  char buf[80]; memset(buf, 0, sizeof(buf));
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tformat); 
  std::string ret = buf;
  return ret;
}

enum {
  DEBUG = 0,
  INFO,
  WARNING,
  ERROR,
  FATAL,
};

int g_log_level = DEBUG;

std::string green_text(const char* text) {
  char buf[256];
  snprintf(buf, sizeof(buf), "%s%s%s", "\e[0;32m", text, "\e[0m");
  return std::string(buf);
}
std::string red_text(const char* text) {
  char buf[256];
  snprintf(buf, sizeof(buf), "%s%s%s", "\e[0;31m", text, "\e[0m");
  return std::string(buf);
}

std::string blue_text(const char* text) {
  char buf[256];
  snprintf(buf, sizeof(buf), "%s%s%s", "\e[0;34m", text, "\e[0m");
  return std::string(buf);
}

void log(int level, const char* file, int line, const char* func, const char *format, ...)
{
  if(level < g_log_level)
    return;
  
  static std::vector<std::string> lvlstrs{"DEBUG", "INFO", "WARNING", "ERROR", "FATAL"};
  auto now = uint32_t(time(NULL));

  std::string lvlstr;
  if(level == INFO)
    lvlstr = green_text(lvlstrs[level].c_str());
  if(level >= WARNING)
    lvlstr = red_text(lvlstrs[level].c_str());
  std::string task = blue_text("match-engine");
  
  char str[512];
  sprintf(str, "%s %s %s:%d %s %s\n", timestamp_2_string(now).c_str(), lvlstr.c_str(), file, line, func, task.c_str());
  printf("%s", str);
  
  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);

  printf("\n");
}

#define LOG(lvl, ...) log((lvl), __FILE__, __LINE__, __func__, __VA_ARGS__)

namespace utils {
  
  template<class T>
  struct Queue
  {
    void push(T const & t)
    {
      {
	std::unique_lock<std::mutex> lk(_mtx);
	_v.push_back(t);
      }
      _cv.notify_one();
    }
    T pop()
    {
      std::unique_lock<std::mutex> lk(_mtx);
      _cv.wait(lk, [this]{ return !_v.empty(); });
      auto t = _v.front();
      _v.pop_front();
      return t;
    }
    bool empty()
    {
      std::unique_lock<std::mutex> lk(_mtx);
      return _v.empty();
    }
  private:
    std::mutex _mtx;
    std::condition_variable _cv;
    std::list<T> _v;
  };
  
} // namespace utils

namespace exchange {
  
  enum {
    TOKEN_BTC = 0,
    TOKEN_USDT,
    TOKEN_MAX,
  };

  enum {
    ORDER_TYPE_DELEGATE_BY_MARKET_PRICE = 0,
    ORDER_TYPE_DELEGATE_BY_LIMIT_PRICE,
    ORDER_TYPE_MAX,
  };

  enum {
    TX_STATUS_INIT = 0,
    TX_STATUS_DONE,
    TX_STATUS_MAX,
  };

  struct Configure
  {
    //static constexpr double initMarketRate = 0.00000005;
    static constexpr double initMarketRate = 0.5;
    static constexpr uint64_t minExchangeNum = 10;
    static constexpr uint64_t maxExchangeNum = 10000;
  };


  struct Order
  {
    Order(){}
    Order(int from, int to , int type, double rate, int num, int minNum, std::string user)
      : _from(from), _to(to), _type(type), _rate(rate), _num(num), _minNum(minNum), _user(user)
    {
      _timeStamp = time(NULL);
      _deadline = _timeStamp + 60;
    }
    int _from;
    int _to;
    int _type;
    double _rate;
    uint64_t _num;
    uint64_t _minNum;
    std::string _user;
    uint32_t _timeStamp;
    uint32_t _deadline;
    bool _matched = false;
    bool _timeout = false;

    int check()
    {
      if(_from == _to)
	return 1;
      if(_from < 0 || _from >= TOKEN_MAX)
	return 2;
      if(_to < 0 || _to >= TOKEN_MAX)
	return 3;
      if(_rate < 0)
	return 4;
      if(_num < Configure::minExchangeNum || _num > Configure::maxExchangeNum)
	return 5;
      if(_minNum > _num)
	return 6;
      if(_user.empty())
	return 7;
      return 0;
    }
    
    void dump()
    {
      printf("order-> from:%d, to:%d, type:%d, rate:%.8f, num:%lu, minNum:%lu, user:%s, timeStamp:%u, dealine:%u, matched:%d, timeout:%d\n"
	     , _from, _to, _type, _rate, _num, _minNum, _user.c_str(), _timeStamp, _deadline, _matched, _timeout);
    }
  };

  struct comparebynum
  {
    bool operator()(const std::shared_ptr<Order>& lhs, const std::shared_ptr<Order>& rhs) const
    {
      return lhs->_num < rhs->_num;
    }
  };

  struct comparebyrate1
  {
    bool operator()(const std::shared_ptr<Order>& lhs, const std::shared_ptr<Order>& rhs) const
    {
      return lhs->_rate < rhs->_rate;
    }
  };

  struct comparebyrate2
  {
    bool operator()(const std::shared_ptr<Order>& lhs, const std::shared_ptr<Order>& rhs) const
    {
      return !(lhs->_rate < rhs->_rate);
    }
  };

  struct comparebydeadline
  {
    bool operator()(const std::shared_ptr<Order>& lhs, const std::shared_ptr<Order>& rhs) const
    {
      return lhs->_deadline < rhs->_deadline;
    }
  };
  
  typedef std::shared_ptr<Order> OrderPtr;
  typedef std::multiset<OrderPtr, comparebynum>  OrderNumSet;
  typedef std::multiset<OrderPtr, comparebyrate1> OrderRateSet1;
  typedef std::multiset<OrderPtr, comparebyrate2> OrderRateSet2;
  
  struct Transaction
  {
    Transaction(OrderPtr d1, OrderPtr d2, double rate, uint64_t num)
      : _order1(d1), _order2(d2), _rate(rate), _num(num)
    {
      _timeStamp = time(NULL);
    }
  
    OrderPtr _order1;
    OrderPtr _order2;
    double _rate;
    uint64_t _num;
    uint32_t _timeStamp;
    int _status = 0;
    
    void dump()
    {
      printf("tx-> \n");
      _order1->dump();
      _order2->dump();
      printf("rate:%.8f, num:%lu, timeStamp:%u status:%d\n", _rate, _num, _timeStamp, _status);
    }
  };

  typedef std::shared_ptr<Transaction> TransactionPtr;

  template<class OrderRateSet>
  struct OrderBook
  {
    typedef OrderRateSet OrderRateSet_t;
    
    OrderBook(bool isSeller)
      : _isSeller(isSeller) {}
  
    int insert(OrderPtr order)
    {
      if(order->_type == ORDER_TYPE_DELEGATE_BY_MARKET_PRICE) {
	_marketPriceOrderQueue.push(order);
	_marketPriceOrderSetByNum.insert(order);
	return 0;
      }

      if(order->_type == ORDER_TYPE_DELEGATE_BY_LIMIT_PRICE) {
	_limitPriceOrderSetByRate.insert(order);
	if(0 == _limitPriceOrderMapByNum.count(order->_num))
	  _limitPriceOrderMapByNum[order->_num] = std::make_shared<OrderRateSet>();
	_limitPriceOrderMapByNum[order->_num]->insert(order);
	return 0;
      }
      
      return -1;
    }

    void remove_order(OrderPtr order)
    {
      // if(order->_type == ORDER_TYPE_DELEGATE_BY_MARKET_PRICE) {
      // 	if(_marketPriceOrderQueue.front() == order)
      // 	  _marketPriceOrderQueue.pop();
      // 	_marketPriceOrderSetByNum;
      // }
    }
    
    bool _isSeller;
    
    std::queue<OrderPtr> _marketPriceOrderQueue;
    OrderNumSet _marketPriceOrderSetByNum;

    OrderRateSet _limitPriceOrderSetByRate;
    std::map<uint64_t, std::shared_ptr<OrderRateSet>> _limitPriceOrderMapByNum;

    std::queue<OrderPtr> _retry4minNumQueue;
  };

  OrderNumSet::iterator num_set_find_nearest(uint64_t num, OrderNumSet & set)
  {
    if(set.empty())
      return set.end();
    if(set.size() == 1)
      return set.begin();

    auto key = std::make_shared<Order>();
    key->_num = num;
    auto pos = set.lower_bound(key);
    if((*pos)->_num == num)
      return pos;
    
    if(pos == set.end()) 
      return --pos;
    
    auto posleft = --pos;
    auto numleft = (*posleft)->_num;
    auto numright = (*pos)->_num;
    auto invl = (numleft > num) ? (numleft - num) : (num - numleft);
    auto invr = (numright > num) ? (numright - num) : (num - numright);
    return (invl <= invr) ? posleft : pos;
  }

  template<class OrderRateSet>
  typename std::map<uint64_t, std::shared_ptr<OrderRateSet>>::iterator
  num_map_find_nearest(uint64_t num, std::map<uint64_t, std::shared_ptr<OrderRateSet>> & map)
  {
    if(map.empty())
      return map.end();
    if(map.size() == 1)
      return map.begin();
    
    auto pos = map.lower_bound(num);
    if(pos->first == num)
      return pos;
    
    if(pos == map.end()) 
      return --pos;
    
    auto posleft = --pos;
    auto invl = (posleft->first > num) ? (posleft->first - num) : (num - posleft->first) ;
    auto invr = (pos->first > num) ? (pos->first - num) : (num - pos->first) ;
    return (invl <= invr) ? posleft : pos;    
  }

  template<class OrderRateSet>
  typename OrderRateSet::iterator find_valid_order_by_rate(double rate, std::shared_ptr<OrderRateSet> & set)
  {
    auto ascending = std::is_same<typename OrderRateSet::key_compare, comparebyrate1>::value;
    auto isSeller = ascending;

    if(isSeller) {
      for(auto it = set->begin(); it != set->end(); ++it)
	if(rate >= (*it)->_rate)
	  return it;
    } else {
      for(auto it = set->begin(); it != set->end(); ++it)
	if((*it)->_rate >= rate)
	  return it;
    }
    
    return set->end();
  }

  struct MatchEngine
  {
    void run(volatile bool* alive)
    {
      LOG(INFO, "MatchEngine::run start!\n");
      
      while(*alive) {

	auto now = uint32_t(time(NULL));

	for(;;) {
	  if(_timeoutQueue.empty())
	    break;
	  auto order = _timeoutQueue.top();
	  if(order->_deadline >= now)
	    break;
	  order->_timeout = true;
	  _timeoutQueue.pop();
	  LOG(INFO, "order timeout!");
	  order->dump();
	}
	
	while(!_qin->empty()){
	  auto order = _qin->pop();
	  LOG(INFO, "order is coming...");
	  order->dump();
	  insert_order(order);
	}
	
	static int cnt = 0;
	int ret;
	if(cnt++%2)
	  ret = do_match(_sellerOrderBook, _buyerOrderBook);
	else
	  ret = do_match(_buyerOrderBook, _sellerOrderBook);
	
	if(ret != 0) {
	  LOG(INFO, "do_match failed with %d", ret);
	  usleep(1000*1000);
	}
      }
      
      LOG(INFO, "MatchEngine::run exit!\n");
    }

    void set_queues(utils::Queue<OrderPtr>* in, utils::Queue<TransactionPtr>* out)
    {
      _qin = in;
      _qout = out;
    }

    double market_rate()
    {
      return _marketRate;
    }
  private:

    bool is_seller(int from, int to)
    {
      return to == TOKEN_BTC;
    }
    
    int insert_order(OrderPtr order)
    {
      int ret = order->check();
      if(ret != 0) {
	LOG(WARNING, "invalid order, error:%d", ret);
	order->dump();
	return ret;
      }
      _timeoutQueue.push(order);
      if(is_seller(order->_from, order->_to))
	return _sellerOrderBook.insert(order);
      else
	return _buyerOrderBook.insert(order);
      return ret;
    }
  
    void update_market_rate(double rate)
    {
      static uint64_t totalcnt = 0;
      int cnt = 10;
    
      if(_lastRates.size() < cnt) 
	_lastRates.push_back(rate);
      else 
	_lastRates[totalcnt%cnt] = rate;
    
      cnt = _lastRates.size();
      double sum = 0;
    
      for(auto a : _lastRates)
	sum += a;
    
      totalcnt++;
    
      _marketRate = sum/cnt;

    }

    bool is_order_rate_match(OrderPtr a, OrderPtr b)
    {
      auto sellerOrder = a->_to == TOKEN_BTC ? a : b;
      auto buyerOrder  = a->_to != TOKEN_BTC ? a : b;
      
      if(sellerOrder->_type == ORDER_TYPE_DELEGATE_BY_MARKET_PRICE)
	sellerOrder->_rate = _marketRate;
      if(buyerOrder->_type == ORDER_TYPE_DELEGATE_BY_MARKET_PRICE)
	buyerOrder->_rate = _marketRate;
      
      return buyerOrder->_rate >= sellerOrder->_rate;
    }
    
    bool check_order_minimal_num(OrderPtr a, OrderPtr b)
    {
      auto sellerOrder = a->_to == TOKEN_BTC ? a : b;
      auto buyerOrder  = a->_to != TOKEN_BTC ? a : b;
      
      auto ret = true;
      auto num = std::min(sellerOrder->_num, buyerOrder->_num);
      
      if(sellerOrder->_minNum > num) {
	_sellerOrderBook._retry4minNumQueue.push(sellerOrder);
	ret = false;
      }
      if(buyerOrder->_minNum > num) {
	_buyerOrderBook._retry4minNumQueue.push(buyerOrder);
	ret = false;
      }
      
      return ret;
    }

    bool check_order_minimal_num(OrderPtr a, uint64_t num)
    {
      return a->_minNum <= num;
    }
    
    bool check_order_timeout(OrderPtr a)
    {
      return a->_timeout;
    }

    bool check_order_matched(OrderPtr a)
    {
      return a->_matched;
    }
    
    void match_handler(OrderPtr a, OrderPtr b)
    {
      auto sellerOrder = a->_to == TOKEN_BTC ? a : b;
      auto buyerOrder  = a->_to != TOKEN_BTC ? a : b;

      if(sellerOrder->_type == ORDER_TYPE_DELEGATE_BY_MARKET_PRICE)
	sellerOrder->_rate = _marketRate;
      if(buyerOrder->_type == ORDER_TYPE_DELEGATE_BY_MARKET_PRICE)
	buyerOrder->_rate = _marketRate;

      if(check_order_matched(a) || check_order_matched(b)) {
	LOG(WARNING, "match_handler check_order_matched failed");
	a->dump();
	b->dump();
	return;
      }
      
      if(!is_order_rate_match(a, b)) {
	LOG(WARNING, "match_handler is_order_rate_match failed");
	a->dump();
	b->dump();
	return;
      }
      
      if(check_order_timeout(a) || check_order_timeout(b)) {
	LOG(WARNING, "match_handler check_order_timeout failed");
	a->dump();
	b->dump();
	return;
      }

      if(a->_matched || b->_matched) {
	LOG(WARNING, "match_handler check matched failed");
	a->dump();
	b->dump();
	return;
      }
      
      if(!check_order_minimal_num(a, b)) {
	LOG(WARNING, "match_handler check_order_minimal_num failed");
	a->dump();
	b->dump();
	return;
      }
      
      double rate = _marketRate;

      if(_marketRate < sellerOrder->_rate)
	rate = sellerOrder->_rate;
      else if(_marketRate > buyerOrder->_rate)
	rate = buyerOrder->_rate;
      
      update_market_rate(rate);
      
      auto ptx = std::make_shared<Transaction>(sellerOrder, buyerOrder, rate, std::min(sellerOrder->_num, buyerOrder->_num));
      _qout->push(ptx);
      
      sellerOrder->_matched = true;
      buyerOrder->_matched = true;
    }

    int handle_orders(OrderPtr a, OrderPtr b, std::function<void()> erasea, std::function<void()> eraseb) {

      LOG(INFO, "handle_orders start...");
      
      if(check_order_timeout(a)) {
	erasea();
	return 11;
      }
      if(check_order_timeout(b)) {
	eraseb();
	return 12;
      }

      if(check_order_matched(a)) {
	erasea();
	return 13;
      }
      if(check_order_matched(b)) {
	eraseb();
	return 14;
      }
      
      check_order_minimal_num(a, b);
      
      auto num = std::min(a->_num, b->_num);
      if(!check_order_minimal_num(a, num)){
	erasea();
	return 15;
      }
      if(!check_order_minimal_num(b, num)) {
	eraseb();
	return 16;
      }
	
      match_handler(a, b);
	
      erasea();
      eraseb();

      LOG(INFO, "handle_orders success...");
      
      return 0;
    };
      
    template<class BOOK1, class BOOK2>
    int do_match(BOOK1 & book1, BOOK2 & book2)
    {
      dot(".");
      
      OrderPtr order;

      std::function<void()> order_erase;
      
      if(!book1._marketPriceOrderQueue.empty()) {
	order = book1._marketPriceOrderQueue.front();
	order_erase = [&]{ book1._marketPriceOrderQueue.pop(); };
      } else if(!book1._limitPriceOrderSetByRate.empty()) {
	auto pos = book1._limitPriceOrderSetByRate.begin();
	order = *pos;
	order_erase = [pos, &book1]{ book1._limitPriceOrderSetByRate.erase(pos); }; 
      } else {
	return 1;
      }

      LOG(DEBUG, "do_match @ 1");

      if(check_order_timeout(order)) {
	order_erase();
	return 2;
      }

      if(check_order_matched(order)) {
	order_erase();
	return 3;
      }
      
      LOG(DEBUG, "do_match @ 2");
      
      {
	auto end = book2._marketPriceOrderSetByNum.end();
	auto pos = book2._marketPriceOrderSetByNum.find(order);
	if(pos != end)  
	  return handle_orders(order, *pos, order_erase, [&]{ book2._marketPriceOrderSetByNum.erase(pos); });
      }

      LOG(DEBUG, "do_match @ 3");
      
      {
	auto end = book2._limitPriceOrderMapByNum.end();
	auto pos = book2._limitPriceOrderMapByNum.find(order->_num);

	if(pos != end) {
	  auto pos1 = find_valid_order_by_rate(order->_rate, pos->second); 
	  if(pos1 != pos->second->end()) 
	    return handle_orders(order, *pos1, order_erase, [&]{ pos->second->erase(pos1); });
	}
      }

      LOG(DEBUG, "do_match @ 4");
      
      {
	auto end = book2._marketPriceOrderSetByNum.end();
	auto pos = num_set_find_nearest(order->_num, book2._marketPriceOrderSetByNum); 
					     
	if(pos != end)  
	  return handle_orders(order, *pos, order_erase, [&]{ book2._marketPriceOrderSetByNum.erase(pos); });
      }

      LOG(DEBUG, "do_match @ 5");

      {
	auto end = book2._limitPriceOrderMapByNum.end();
	auto pos = num_map_find_nearest(order->_num, book2._limitPriceOrderMapByNum);
	
	if(pos != end) {
	  auto pos1 = find_valid_order_by_rate(order->_rate, pos->second); 
	  if(pos1 != pos->second->end()) 
	    return handle_orders(order, *pos1, order_erase, [&]{ pos->second->erase(pos1); });
	}
      }

      LOG(DEBUG, "do_match @ 6");
      
      {
	auto end = book2._limitPriceOrderSetByRate.end();
	auto pos = book2._limitPriceOrderSetByRate.begin();

	if(pos != end) {
	  if(is_order_rate_match(order, *pos)) 
	    return handle_orders(order, *pos, order_erase, [&]{ book2._limitPriceOrderSetByRate.erase(pos); });
	}
      }

      LOG(DEBUG, "do_match @ 7");
      
      if(order->_type == ORDER_TYPE_DELEGATE_BY_MARKET_PRICE) {
	if(!book1._limitPriceOrderSetByRate.empty()) {
	  auto pos = book1._limitPriceOrderSetByRate.begin();
	  order = *pos;
	  order_erase = [pos, &book1]{ book1._limitPriceOrderSetByRate.erase(pos); };
	  {
	    auto end = book2._limitPriceOrderSetByRate.end();
	    auto pos = book2._limitPriceOrderSetByRate.begin();
	    if(pos != end) {
	      if(is_order_rate_match(order, *pos)) 
		return handle_orders(order, *pos, order_erase, [&]{ book2._limitPriceOrderSetByRate.erase(pos); });
	    }
	  }
	} 
      }

      LOG(DEBUG, "do_match @ 8");
      
      if(!book2._retry4minNumQueue.empty()) {
	auto order2 = book2._retry4minNumQueue.front();
	if(is_order_rate_match(order, order2))
	  return handle_orders(order, order2, order_erase, [&]{ book2._retry4minNumQueue.pop(); });
	else {
	  book2._retry4minNumQueue.pop();
	  book2._retry4minNumQueue.push(order2);
	}
      }

      LOG(DEBUG, "do_match @ 9");
      
      return 4;
    }

    utils::Queue<OrderPtr>* _qin{nullptr};
    utils::Queue<TransactionPtr>* _qout{nullptr};
    
    std::vector<double> _lastRates;
    double _marketRate = Configure::initMarketRate;
  
    OrderBook<OrderRateSet1> _sellerOrderBook{true};
    OrderBook<OrderRateSet2> _buyerOrderBook{false};

    std::priority_queue<OrderPtr, std::vector<OrderPtr>, comparebydeadline> _timeoutQueue;
  };

} // namespace exchange

int main()
{
  volatile bool alive = true;
  exchange::MatchEngine engine;
  
  utils::Queue<exchange::OrderPtr> qorder;
  utils::Queue<exchange::TransactionPtr> qtx;
  
  engine.set_queues(&qorder, &qtx);

  std::thread orderGenerator([&]{
      // from, to, type, rate, num, minNum, user, timeStamp

      sleep(1);

      printf("\nmarket rate:  %.8f\n", engine.market_rate());
      qorder.push(std::make_shared<exchange::Order>(0, 1, 1, 0.66, 10, 0, "alice3"));
      qorder.push(std::make_shared<exchange::Order>(1, 0, 1, 0.44, 20, 0, "bob3"));
      
      sleep(30);
      
      printf("\nmarket rate:  %.8f\n", engine.market_rate());
      qorder.push(std::make_shared<exchange::Order>(0, 1, 1, 0.66, 30, 0, "alice4"));
      qorder.push(std::make_shared<exchange::Order>(1, 0, 1, 0.65, 20, 0, "bob4"));
      
      sleep(1);

      printf("\nmarket rate:  %.8f\n", engine.market_rate());
      qorder.push(std::make_shared<exchange::Order>(0, 1, 1, 0.36, 30, 0, "alice5"));
      qorder.push(std::make_shared<exchange::Order>(1, 0, 1, 0.35, 30, 0, "bob5"));

      sleep(1);

      printf("\nmarket rate:  %.8f\n", engine.market_rate());
      qorder.push(std::make_shared<exchange::Order>(0, 1, 0, 0.00, 30, 0, "alice6"));
      qorder.push(std::make_shared<exchange::Order>(1, 0, 0, 0.00, 40, 0, "bob6"));
      
    });
  
  std::thread matchProc(&exchange::MatchEngine::run, &engine, &alive);
  
  std::thread txDumpProc([&]{
      for(;;) {
	auto tx = qtx.pop();
	tx->dump();
      }
    });
  
  orderGenerator.join();
  matchProc.join();
  txDumpProc.join();
  
  return 0;
}
