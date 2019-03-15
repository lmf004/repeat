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

int g_log_level = INFO;

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
    static constexpr uint64_t minExchangeNum = 1;
    static constexpr uint64_t maxExchangeNum = 10000;
  };


  struct Order
  {
    static uint32_t gcnt;
    
    Order(){ gcnt++; }
    Order(int idx, int from, int to , int type, double rate, int num, int minNum, std::string user)
      : _idx(idx), _from(from), _to(to), _type(type), _rate(rate), _num(num), _minNum(minNum), _user(user)
    {
      _timeStamp = time(NULL);
      _deadline = _timeStamp + 3600;
      gcnt++;
    }
    ~Order(){
      if(!_matched && !_timeout) {
	LOG(ERROR, "order is deleted wrongly");
	printf("this: %p\n", this);
	dump();
      }
      gcnt--;
    }

    int _idx;
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

    std::string string()
    {
      char text[512];
      sprintf(text, "{idx:%d, from:%d,to:%d,type:%d,rate:%.8f,num:%lu,minNum:%lu,user:%s,timeStamp:%u,dealine:%u,matched:%d,timeout:%d}"
	      , _idx, _from, _to, _type, _rate, _num, _minNum, _user.c_str(), _timeStamp, _deadline, _matched, _timeout);
      return std::string(text);
    }
    
    void dump()
    {
      printf("order -> idx:%d, from:%d, to:%d, type:%d, rate:%.8f, num:%lu, minNum:%lu, user:%s, timeStamp:%u, dealine:%u, matched:%d, timeout:%d, gcnt:%u\n"
	     , _idx, _from, _to, _type, _rate, _num, _minNum, _user.c_str(), _timeStamp, _deadline, _matched, _timeout, gcnt);
    }
  };

  uint32_t Order::gcnt = 0;
  
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

  template<class Container, class Element>
  void remove_if_ex(Container & v, std::function<bool(Element)> func)
  {
    for(auto it = v.begin(); it != v.end();) {
      if(func(*it))
	it = v.erase(it);
      else
	it++;
    }
  }
  
  typedef std::shared_ptr<Order> OrderPtr;
  typedef std::multiset<OrderPtr, comparebynum>  OrderNumSet;
  typedef std::multiset<OrderPtr, comparebyrate1> OrderRateSet1;
  typedef std::multiset<OrderPtr, comparebyrate2> OrderRateSet2;
  
  struct Transaction
  {
    Transaction(OrderPtr d1, OrderPtr d2, double rate, uint64_t num)
      : _rate(rate), _num(num)
    {
      _timeStamp = time(NULL);
      _order1 = d1->string();
      _order2 = d2->string();
    }
  
    std::string _order1;
    std::string _order2;
    double _rate;
    uint64_t _num;
    uint32_t _timeStamp;
    int _status = 0;
    
    void dump()
    {
      printf("tx-> \n");
      printf("%s\n%s\nrate:%.8f, num:%lu, timeStamp:%u status:%d\n", _order1.c_str(), _order2.c_str(), _rate, _num, _timeStamp, _status);
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

    void remove_cached_invalid_order()
    {
      std::function<bool(OrderPtr)> func =
	[](OrderPtr order){ return order->_matched || order->_timeout; };
      
      remove_if_ex(_marketPriceOrderSetByNum, func);
      
      for(auto it = _limitPriceOrderMapByNum.begin(); it != _limitPriceOrderMapByNum.end(); ++it)
	remove_if_ex(*(it->second), func);

      remove_if_ex(_retry4minNumQueue, func);
    }

    void dump()
    {
      // printf("OrderBook -> isSeller:%d, marketPriceOrderQueue:%lu, marketPriceOrderSetByNum:%lu, limitPriceOrderSetByRate:%lu retry4minNumQueue:%lu\n",
      // 	     _isSeller, _marketPriceOrderQueue.size(), _marketPriceOrderSetByNum.size(), _limitPriceOrderSetByRate.size(), _retry4minNumQueue.size());
      // printf("---------001\n");
      // for(auto a : _limitPriceOrderSetByRate)
      // 	a->dump();
      // printf("---------002\n");
    }
    
    bool _isSeller;
    
    std::queue<OrderPtr> _marketPriceOrderQueue;
    OrderNumSet _marketPriceOrderSetByNum;

    OrderRateSet _limitPriceOrderSetByRate;
    std::map<uint64_t, std::shared_ptr<OrderRateSet>> _limitPriceOrderMapByNum;

    std::list<OrderPtr> _retry4minNumQueue;
  };

  OrderNumSet::iterator num_set_find_nearest(uint64_t num, OrderNumSet & set)
  {
    if(set.empty())
      return set.end();
    if(set.size() == 1)
      return set.begin();

    //auto key = std::make_shared<Order>();
    static std::shared_ptr<Order> key(new Order);
    key->_num = num;
    auto pos = set.lower_bound(key);
    if(pos == set.begin())
      return pos;
    if(pos == set.end()) 
      return --pos;
    if((*pos)->_num == num)
      return pos;
    
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
    if(pos == map.begin()) 
      return pos;
    if(pos == map.end()) 
      return --pos;
    if(pos->first == num)
      return pos;
    
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
	  auto pos = _timeoutQueue.begin();
	  auto order = *pos;
	  if(order->_matched) {
	    _timeoutQueue.erase(pos);
	    continue;
	  }
	  if(order->_deadline >= now)
	    break;
	  order->_timeout = true;
	  _timeoutQueue.erase(pos);
	  if(!order->_matched)
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
	  LOG(DEBUG, "do_match return with %d", ret);

	  static uint32_t last = 0;
	  if(now % 8 == 0 && now != last) {
	    
	    dot(".");
	    
	    _sellerOrderBook.remove_cached_invalid_order();
	    _buyerOrderBook.remove_cached_invalid_order();
	    
	    std::function<bool(OrderPtr)> func = [](OrderPtr order){ return order->_matched; };
	    remove_if_ex(_timeoutQueue, func);

	    // _sellerOrderBook.dump();
	    // _buyerOrderBook.dump();
	    // printf("timeoutQueue:%lu\n", _timeoutQueue.size());

	    auto a = _buyerOrderBook._marketPriceOrderQueue.size()+_buyerOrderBook._limitPriceOrderSetByRate.size()+_buyerOrderBook._retry4minNumQueue.size();
	    auto b = _sellerOrderBook._marketPriceOrderQueue.size()+_sellerOrderBook._limitPriceOrderSetByRate.size()+_sellerOrderBook._retry4minNumQueue.size();
	    
	    if(Order::gcnt > 0)
	      LOG(INFO, "order gcnt: %u, buyers:%lu, sellers:%lu", Order::gcnt, a, b);
	    last = now;
	  }

	  //usleep(1*1000);
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
      _timeoutQueue.insert(order);
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

    bool is_order_alive(OrderPtr a)
    {
      return a->_matched == false && a->_timeout == false;
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

    bool is_order_mininal_num_match(OrderPtr a, OrderPtr b)
    {
      auto num = std::min(a->_num, b->_num);
      return a->_minNum <= num && b->_minNum <= num;
    }
    
    bool is_order_match(OrderPtr a, OrderPtr b)
    {
      return is_order_rate_match(a, b) && is_order_mininal_num_match(a, b);
    }
      
    bool check_order_minimal_num(OrderPtr a, OrderPtr b)
    {
      auto sellerOrder = a->_to == TOKEN_BTC ? a : b;
      auto buyerOrder  = a->_to != TOKEN_BTC ? a : b;
      
      auto ret = true;
      auto num = std::min(sellerOrder->_num, buyerOrder->_num);
      
      if(sellerOrder->_minNum > num) {
	_sellerOrderBook._retry4minNumQueue.push_back(sellerOrder);
	ret = false;
      }
      if(buyerOrder->_minNum > num) {
	_buyerOrderBook._retry4minNumQueue.push_back(buyerOrder);
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

      sellerOrder->_matched = true;
      buyerOrder->_matched = true;

      auto ptx = std::make_shared<Transaction>(sellerOrder, buyerOrder, rate, std::min(sellerOrder->_num, buyerOrder->_num));
      _qout->push(ptx);
      
    }

    int handle_orders(OrderPtr a, OrderPtr b, std::function<void()> erasea, std::function<void()> eraseb) {

      LOG(DEBUG, "handle_orders start...");
      
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

      if(!is_order_rate_match(a, b)){
	LOG(ERROR, "handle_orders is_order_rate_match failed");
	erasea();
	eraseb();
	return 15;
      }
      
      check_order_minimal_num(a, b);
      
      auto num = std::min(a->_num, b->_num);
      if(!check_order_minimal_num(a, num)){
	erasea();
	return 16;
      }
      if(!check_order_minimal_num(b, num)) {
	eraseb();
	return 17;
      }
	
      match_handler(a, b);
	
      erasea();
      eraseb();

      static int i = 0;
      LOG(INFO, "handle_orders success... %d", i++);
      
      return 0;
    };

    template<class BOOK1, class BOOK2>
    int do_match(BOOK1 & book1, BOOK2 & book2)
    {
      int ret = -1;
      OrderPtr order;
      std::function<void()> order_erase;
      
      if(!book1._marketPriceOrderQueue.empty()) {
	order = book1._marketPriceOrderQueue.front();
	order_erase = [&]{ book1._marketPriceOrderQueue.pop(); };
	ret = do_one_match(book1, book2, order, order_erase);
	if(0 == ret) return 0;
      }

      if(!book1._limitPriceOrderSetByRate.empty()) {
      	auto pos = book1._limitPriceOrderSetByRate.begin();
      	order = *pos;
      	//order_erase = [pos, &book1]{ book1._limitPriceOrderSetByRate.erase(pos); };
	order_erase = [&]{ book1._limitPriceOrderSetByRate.erase(pos); };
      	ret = do_one_match(book1, book2, order, order_erase);
      	if(0 == ret) return 0;
      }

      if(!book1._retry4minNumQueue.empty()) {
      	bool poped = false;
      	order = book1._retry4minNumQueue.front();
      	order_erase = [&]{ book1._retry4minNumQueue.pop_front(); poped = true; };
      	ret = do_one_match(book1, book2, order, order_erase);
      	if(0 == ret) return 0;
      	if(is_order_alive(order) && false == poped) {
      	  book1._retry4minNumQueue.pop_front();
      	  book1._retry4minNumQueue.push_back(order);
      	}
      }

      usleep(1*1000);
      return ret;
    }
    
    template<class BOOK1, class BOOK2>
    int do_one_match(BOOK1 & book1, BOOK2 & book2, OrderPtr order, std::function<void()> order_erase)
    {
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
	if(pos != end && is_order_rate_match(order, *pos))  
	  return handle_orders(order, *pos, order_erase, [&]{ book2._marketPriceOrderSetByNum.erase(pos); });
      }

      LOG(DEBUG, "do_match @ 3");
      
      {
	auto end = book2._limitPriceOrderMapByNum.end();
	auto pos = book2._limitPriceOrderMapByNum.find(order->_num);

	if(pos != end) {
	  auto pos1 = find_valid_order_by_rate(order->_rate, pos->second); 
	  if(pos1 != pos->second->end() && is_order_rate_match(order, *pos1)) 
	    return handle_orders(order, *pos1, order_erase, [&]{ pos->second->erase(pos1); });
	}
      }

      LOG(DEBUG, "do_match @ 4");
      
      {
	auto end = book2._marketPriceOrderSetByNum.end();
	auto pos = num_set_find_nearest(order->_num, book2._marketPriceOrderSetByNum); 
					     
	if(pos != end && is_order_rate_match(order, *pos))  
	  return handle_orders(order, *pos, order_erase, [&]{ book2._marketPriceOrderSetByNum.erase(pos); });
      }

      LOG(DEBUG, "do_match @ 5");

      {
	auto end = book2._limitPriceOrderMapByNum.end();
	auto pos = num_map_find_nearest(order->_num, book2._limitPriceOrderMapByNum);
	
	if(pos != end) {
	  auto pos1 = find_valid_order_by_rate(order->_rate, pos->second); 
	  if(pos1 != pos->second->end() && is_order_rate_match(order, *pos1)) 
	    return handle_orders(order, *pos1, order_erase, [&]{ pos->second->erase(pos1); });
	}
      }

      LOG(DEBUG, "do_match @ 6");
      
      {
	auto end = book2._limitPriceOrderSetByRate.end();
	auto pos = book2._limitPriceOrderSetByRate.begin();

	if(pos != end && is_order_rate_match(order, *pos)) {
	  return handle_orders(order, *pos, order_erase, [&]{ book2._limitPriceOrderSetByRate.erase(pos); });
	}
      }

      LOG(DEBUG, "do_match @ 7");

      for(auto it=book2._retry4minNumQueue.begin(); it != book2._retry4minNumQueue.end(); ++it) {
      	auto order2 = *it;
      	if(!is_order_match(order, order2))
      	  continue;
      	return handle_orders(order, order2, order_erase, [&]{ book2._retry4minNumQueue.erase(it); });
      }
      
      LOG(DEBUG, "do_match @ 8");

      return 4;
    }

    utils::Queue<OrderPtr>* _qin{nullptr};
    utils::Queue<TransactionPtr>* _qout{nullptr};
    
    std::vector<double> _lastRates;
    double _marketRate = Configure::initMarketRate;
  
    OrderBook<OrderRateSet1> _sellerOrderBook{true};
    OrderBook<OrderRateSet2> _buyerOrderBook{false};

    std::multiset<OrderPtr, comparebydeadline> _timeoutQueue;
  };

} // namespace exchange

int main()
{
  volatile bool alive = true;
  exchange::MatchEngine engine;
  
  utils::Queue<exchange::OrderPtr> qorder;
  utils::Queue<exchange::TransactionPtr> qtx;
  
  engine.set_queues(&qorder, &qtx);

  bool done = false;
  
  std::thread orderGenerator([&]{
      // from, to, type, rate, num, minNum, user, timeStamp

      std::vector<double> v;
      for(int i=1; i<100; ++i)
	v.push_back(0.001*i);
      std::random_shuffle(v.begin(),v.end());

      std::vector<int> v1;
      for(int i=1; i<500; ++i)
	v1.push_back(i%100);
      std::random_shuffle(v1.begin(),v1.end());

      static int idx = 0;
      
      for(int i=0; i<100; i++) {

	//sleep(1);
	for(int j=0; j<v.size(); ) {
	  auto type = (i%3 == 0) ? 0 : 1;
	  qorder.push(std::make_shared<exchange::Order>(idx++, 0, 1, type, 0.5+v[j], v1[j%v1.size()], v1[j%v1.size()]/2, "alice3"));
	  j++;
	  qorder.push(std::make_shared<exchange::Order>(idx++, 1, 0, type, v[j], v1[j%v1.size()], v1[j%v1.size()]/2, "bob3"));
	  j++;
	  //qorder.push(std::make_shared<exchange::Order>(0, 1, type, 1+v[j], v1[j%v1.size()], 0, "alice3"));
	  //qorder.push(std::make_shared<exchange::Order>(1, 0, type, v[j], v1[j%v1.size()], 0, "bob3"));
	}
      }

      done = true;
      for(;;) {
      	int a;
      	std::cin >> a;
      	if(a == 0)
      	  for(int i=0; i<1000; i++) {
      	    qorder.push(std::make_shared<exchange::Order>(idx++, 0, 1, 1, 0.99, 50, 0, "alice3"));
      	  }
      	else
      	  for(int i=0; i<1000; i++) {
      	    qorder.push(std::make_shared<exchange::Order>(idx++, 1, 0, 1, 0.01, 50, 0, "bob3"));
      	  }
      }

    });

  printf("-----------------000\n");
  while(!done) sleep(1);
  printf("-----------------001\n");
  
  std::thread matchProc(&exchange::MatchEngine::run, &engine, &alive);
  
  std::thread txDumpProc([&]{
      //sleep(300);
      for(;;) {
	auto tx = qtx.pop();
	static int i = 0;
	printf("%d ", i++);
	tx->dump();
      }
    });
  
  orderGenerator.join();
  matchProc.join();
  txDumpProc.join();
  
  return 0;
}
