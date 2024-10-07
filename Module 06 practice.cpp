#include <iostream>
#include <fstream>
#include <string>
#include <mutex>
#include <memory>
#include <thread>
#include <vector>
#include <sstream>
#include <ctime>
#include <sys/stat.h>
#include <json/json.h> // Библиотека для работы с JSON

// уровни логирования
enum class LogLevel {
    INFO,
    WARNING,
    ERROR
};

// Одиночка
class Logger {
private:
    static std::unique_ptr<Logger> instance; // Единственный экземпляр
    static std::mutex mtx;                  // Мьютекс для потокобезопасности
    std::ofstream logFile;                  // Файл логов
    LogLevel currentLogLevel;               // Нынешний уровень логирования
    std::string logFileName;                // Имя файла логов
    size_t maxFileSize;                     // Макс размер файла

    // Приватный конструктор для предотвращения создания объектов извне
    Logger(const std::string& filename, LogLevel logLevel, size_t maxSize)
        : logFileName(filename), currentLogLevel(logLevel), maxFileSize(maxSize) {
        OpenLogFile();
    }

    // Открытие файла логов
    void OpenLogFile() {
        logFile.open(logFileName, std::ios::app);
        if (!logFile.is_open()) {
            throw std::runtime_error("Failed to open log file");
        }
    }

    // Проверка размера файла и ротация
    void RotateLogFileIfNeeded() {
        struct stat fileStatus;
        if (stat(logFileName.c_str(), &fileStatus) == 0 && fileStatus.st_size >= maxFileSize) {
            logFile.close();
            std::string newFileName = logFileName + "." + GetCurrentTime();
            rename(logFileName.c_str(), newFileName.c_str());
            OpenLogFile();
        }
    }

    // Получение текущего времени и ротация
    std::string GetCurrentTime() {
        std::time_t now = std::time(nullptr);
        char buf[100];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d_%H-%M-%S", std::localtime(&now));
        return buf;
    }

public:
    // Запрет копирования и присваивания
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    // Метод для получения единственного экземпляра класса Logger
    static Logger* GetInstance(const std::string& configFilePath = "config.json") {
        std::lock_guard<std::mutex> lock(mtx);
        if (!instance) {
            // Загрузка конфигурации из файла
            std::ifstream configFile(configFilePath);
            if (!configFile.is_open()) {
                throw std::runtime_error("Failed to open config file");
            }

            Json::Value config;
            configFile >> config;
            std::string logFileName = config["logFile"].asString();
            LogLevel logLevel = static_cast<LogLevel>(config["logLevel"].asInt());
            size_t maxSize = config["maxFileSize"].asUInt();

            instance.reset(new Logger(logFileName, logLevel, maxSize));
        }
        return instance.get();
    }

    // Установка уровня логирования
    void SetLogLevel(LogLevel level) {
        std::lock_guard<std::mutex> lock(mtx);
        currentLogLevel = level;
    }

    // Логирование сообщений
    void Log(const std::string& message, LogLevel level) {
        std::lock_guard<std::mutex> lock(mtx);
        if (level >= currentLogLevel) {
            RotateLogFileIfNeeded();
            logFile << "[" << GetLogLevelString(level) << "] " << message << std::endl;
        }
    }

    ~Logger() {
        if (logFile.is_open()) {
            logFile.close();
        }
    }

private:
    // Доп. метод для получения строки, соответствующей уровню логирования
    std::string GetLogLevelString(LogLevel level) {
        switch (level) {
            case LogLevel::INFO: return "INFO";
            case LogLevel::WARNING: return "WARNING";
            case LogLevel::ERROR: return "ERROR";
            default: return "";
        }
    }
};

// Инициализация значимых членов класса
std::unique_ptr<Logger> Logger::instance = nullptr;
std::mutex Logger::mtx;


class LogReader {
public:
    static void ReadLogs(const std::string& filename, LogLevel levelFilter) {
        std::ifstream logFile(filename);
        if (!logFile.is_open()) {
            std::cerr << "Failed to open log file for reading." << std::endl;
            return;
        }

        std::string line;
        while (std::getline(logFile, line)) {
            if (ShouldDisplayLine(line, levelFilter)) {
                std::cout << line << std::endl;
            }
        }
    }

private:
    // Фильтрация сообщений по уровню логирования
    static bool ShouldDisplayLine(const std::string& line, LogLevel levelFilter) {
        if (line.find("[ERROR]") != std::string::npos && levelFilter <= LogLevel::ERROR) {
            return true;
        }
        if (line.find("[WARNING]") != std::string::npos && levelFilter <= LogLevel::WARNING) {
            return true;
        }
        if (line.find("[INFO]") != std::string::npos && levelFilter == LogLevel::INFO) {
            return true;
        }
        return false;
    }
};

// Функция для тестирования многопоточности
void LogMessages(int id, LogLevel level) {
    auto logger = Logger::GetInstance();
    logger->Log("Thread " + std::to_string(id) + " started logging.", level);
    logger->Log("Thread " + std::to_string(id) + " is doing work.", LogLevel::INFO);
    logger->Log("Thread " + std::to_string(id) + " encountered a warning.", LogLevel::WARNING);
    logger->Log("Thread " + std::to_string(id) + " encountered an error.", LogLevel::ERROR);
}

int main() {
    // Тестирование многопоточности
    std::vector<std::thread> threads;

    // Запуск нескольких потоков
    for (int i = 0; i < 5; ++i) {
        threads.emplace_back(LogMessages, i, LogLevel::INFO);
    }

    // Ожидание завершения потоков
    for (auto& t : threads) {
        t.join();
    }

    // Чтение логов с фильтрацией по уровню
    LogReader::ReadLogs("app.log", LogLevel::ERROR);

    return 0;
}
