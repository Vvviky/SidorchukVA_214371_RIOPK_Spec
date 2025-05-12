# Программное средство реализации финансового решения "Оплата в рассрочку"

## Описание проекта
Данный проект представляет собой систему управления рассрочками платежей, которая позволяет клиентам оформлять рассрочки на товары/услуги, а администраторам управлять этими рассрочками и шаблонами.

## Архитектура системы

### Общая структура
Система построена на основе микросервисной архитектуры и включает следующие компоненты:
- React Frontend App - клиентское веб-приложение
- API Gateway - шлюз для маршрутизации запросов
- Auth Service - сервис аутентификации
- Business Logic Service - сервис бизнес-логики
- Database - база данных PostgreSQL
  
![1](https://github.com/user-attachments/assets/a6953e55-cb94-455f-a73e-366b0c26b027)
![2](https://github.com/user-attachments/assets/9ae29529-1b84-4484-9772-463ef39a5c22)
![3](https://github.com/user-attachments/assets/b97f1a42-645a-45aa-8b0d-66935576f232)
![4](https://github.com/user-attachments/assets/e2ff18d8-b6f2-45bd-bd7f-47547d17066a)

### Основные модули
1. **Модуль аутентификации (Auth Service)**
   - Управление пользователями
   - Аутентификация и авторизация
   - Управление сессиями

2. **Модуль бизнес-логики (Business Logic Service)**
   - Управление рассрочками
   - Управление шаблонами рассрочек
   - Обработка платежей
   - Расчет графиков платежей

3. **Клиентский модуль (Frontend)**
   - Интерфейс клиента
   - Интерфейс администратора
   - Панель управления

## Структура базы данных
![7](https://github.com/user-attachments/assets/a8fdd706-7342-4032-93c7-4db4802d095d)

## Функциональность

### Диаграмма вариантов использования

![13](https://github.com/user-attachments/assets/9251a90d-cde5-404d-a796-8b5984a074e0)

### Для администраторов
![5](https://github.com/user-attachments/assets/50259862-fcca-4960-b578-e3e4db3530dd)

### Для клиентов

![6](https://github.com/user-attachments/assets/483b35cf-1b20-465a-8fd8-a321b0f2d6d4)


## Детали реализации 
## UML диаграммы 
![8](https://github.com/user-attachments/assets/5b935fff-24a9-4a4b-b384-11f3f551e2a2)

![9](https://github.com/user-attachments/assets/5c6f7060-fa4c-4a26-8537-06dd9850e1ba)

![10](https://github.com/user-attachments/assets/e02e8395-2e81-48ee-bc1c-08ab877fb96a)

![11](https://github.com/user-attachments/assets/2f98ca34-7116-4a79-832b-c924c83c8f29)

![12](https://github.com/user-attachments/assets/1298eaa2-b985-4ffe-9ac1-9692fa5f6b63)

## API Спецификация

### Auth Service API

#### Аутентификация
- POST /api/auth/register - Регистрация нового пользователя
- POST /api/auth/login - Вход в систему
- POST /api/auth/logout - Выход из системы
- GET /api/auth/refresh - Обновление токена
- GET /api/auth/me - Получение информации о текущем пользователе

#### Управление пользователями (только для администраторов)
- GET /api/users - Получение списка пользователей
- GET /api/users/:id - Получение информации о пользователе
- PUT /api/users/:id - Обновление информации пользователя
- DELETE /api/users/:id - Удаление пользователя

### Business Service API

#### Шаблоны рассрочек

#### GET /api/templates
Получение списка шаблонов рассрочек.

**Response:**
```json
{
  "templates": [
    {
      "id": "uuid",
      "name": "Стандартная рассрочка",
      "description": "Рассрочка на 12 месяцев",
      "minAmount": 1000,
      "maxAmount": 100000,
      "availableTerms": [3, 6, 12],
      "defaultTerm": 12,
      "currency": "RUB",
      "requiresApproval": true,
      "isActive": true
    }
  ],
  "total": 1
}
```

#### POST /api/templates
Создание нового шаблона (только для администраторов).

**Request:**
```json
{
  "name": "Стандартная рассрочка",
  "description": "Рассрочка на 12 месяцев",
  "minAmount": 1000,
  "maxAmount": 100000,
  "availableTerms": [3, 6, 12],
  "defaultTerm": 12,
  "currency": "RUB",
  "requiresApproval": true
}
```

### Рассрочки

#### POST /api/installments
Создание новой рассрочки.

**Request:**
```json
{
  "templateId": "uuid",
  "amount": 50000,
  "term": 12,
  "title": "Покупка ноутбука",
  "description": "MacBook Pro 13"
}
```

**Response:**
```json
{
  "id": "uuid",
  "status": "PENDING_APPROVAL",
  "totalAmount": 50000,
  "term": 12,
  "monthlyPayment": 4166.67,
  "startDate": "2024-03-20T00:00:00Z",
  "endDate": "2025-03-20T00:00:00Z",
  "payments": [
    {
      "id": "uuid",
      "dueDate": "2024-04-20T00:00:00Z",
      "amount": 4166.67,
      "status": "PENDING"
    }
  ]
}
```

## Безопасность

### Валидация данных

```javascript
const validateInstallmentRequest = (data) => {
  const schema = Joi.object({
    templateId: Joi.string().uuid().required(),
    amount: Joi.number().min(1000).max(100000).required(),
    term: Joi.number().valid(3, 6, 12).required(),
    title: Joi.string().min(3).max(100).required(),
    description: Joi.string().max(500)
  });
  
  return schema.validate(data);
};
```

### Проверка прав доступа

```javascript
const checkInstallmentAccess = async (req, res, next) => {
  const installment = await Installment.findById(req.params.id);
  if (!installment) {
    return res.status(404).json({ message: 'Installment not found' });
  }
  
  if (req.user.role !== 'ADMIN' && installment.userId !== req.user.id) {
    return res.status(403).json({ message: 'Access denied' });
  }
  
  req.installment = installment;
  next();
};
```

### Безопасная обработка платежей

```javascript
const processPayment = async (installmentId, amount) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const installment = await Installment.findById(installmentId).session(session);
    if (!installment) {
      throw new Error('Installment not found');
    }
    
    const payment = await Payment.create([{
      installmentId,
      amount,
      status: 'PROCESSING'
    }], { session });
    
    // Интеграция с платежной системой
    const paymentResult = await paymentGateway.processPayment({
      amount,
      currency: installment.currency,
      description: `Payment for installment ${installmentId}`
    });
    
    if (paymentResult.status === 'success') {
      payment.status = 'COMPLETED';
      installment.paidAmount += amount;
      
      if (installment.paidAmount >= installment.totalAmount) {
        installment.status = 'COMPLETED';
      }
      
      await payment.save({ session });
      await installment.save({ session });
      await session.commitTransaction();
      
      return { success: true, payment };
    } else {
      throw new Error('Payment failed');
    }
  } catch (error) {
    await session.abortTransaction();
    throw error;
  } finally {
    session.endSession();
  }
};
```
## API Endpoints

### Аутентификация

#### POST /api/auth/register
Регистрация нового пользователя.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "password123",
  "firstName": "John",
  "lastName": "Doe"
}
```

**Response:**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "role": "USER",
  "token": "jwt-token"
}
```

#### POST /api/auth/login
Вход в систему.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "token": "jwt-token",
  "refreshToken": "refresh-token"
}
```

### Управление пользователями

#### GET /api/users
Получение списка пользователей (только для администраторов).

**Response:**
```json
{
  "users": [
    {
      "id": "uuid",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "role": "USER",
      "isActive": true,
      "lastLogin": "2024-03-20T12:00:00Z"
    }
  ],
  "total": 1
}
```

## Безопасность

### JWT Токены

- Access Token: срок действия 1 час
- Refresh Token: срок действия 30 дней
- Хранение в httpOnly cookies
- Автоматическое обновление через refresh token

### Хеширование паролей

```javascript
const bcrypt = require('bcrypt');

const hashPassword = async (password) => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
};

const verifyPassword = async (password, hash) => {
  return bcrypt.compare(password, hash);
};
```

### Middleware

#### Проверка аутентификации

```javascript
const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};
```

#### Проверка роли

```javascript
const checkRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied' });
    }
    next();
  };
};
```

## Безопасность

### Аутентификация и авторизация

1. **JWT (JSON Web Tokens)**
   - Используется для безопасной передачи информации между сервисами
   - Токены содержат информацию о пользователе и его правах
   - Реализована система refresh-токенов для безопасного обновления доступа

```javascript
const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};
```

2. **Ролевая система доступа (RBAC)**
   - Разграничение прав доступа на основе ролей пользователей
   - Поддерживаемые роли: USER, ADMIN
   - Проверка прав доступа на уровне middleware

```javascript
// Пример middleware для проверки роли
const checkRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied' });
    }
    next();
  };
};
```

### Безопасное хранение данных

1. **Шифрование паролей**
   - Использование bcrypt для хеширования паролей
   - Соль генерируется автоматически
   - Минимальная длина пароля - 8 символов

```javascript
const hashPassword = async (password) => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
};
```

2. **Защита чувствительных данных**
   - Шифрование данных банковских карт
   - Маскирование чувствительной информации в логах
   - Безопасное хранение секретов в .env файлах

3. **Логирование и мониторинг**
   - Ведение журналов безопасности
   - Мониторинг подозрительной активности
   - Система оповещений о критических событиях

## Тестирование

### Unit-тесты

#### calculation.service.test
```javascript
const calculationService = require('../calculation.service');
const ApiError = require('../../utils/ApiError');

describe('CalculationService', () => {
  describe('calculateMonthlyPayment', () => {
    it('should calculate correct monthly payment', () => {
      const result = calculationService.calculateMonthlyPayment(100000, 12, 10);
      expect(result).toBeCloseTo(8791.59, 2);
    });

    it('should throw error for invalid parameters', () => {
      expect(() => calculationService.calculateMonthlyPayment(0, 12, 10)).toThrow(ApiError);
      expect(() => calculationService.calculateMonthlyPayment(100000, 0, 10)).toThrow(ApiError);
      expect(() => calculationService.calculateMonthlyPayment(100000, 12, -1)).toThrow(ApiError);
    });
  });

  describe('calculatePaymentSchedule', () => {
    it('should calculate correct payment schedule', () => {
      const result = calculationService.calculatePaymentSchedule(100000, 12, 10);
      
      expect(result.schedule).toHaveLength(12);
      expect(result.totalAmount).toBeCloseTo(105499.08, 2);
      expect(result.overpayment).toBeCloseTo(5499.08, 2);

      const firstPayment = result.schedule[0];
      expect(firstPayment.paymentNumber).toBe(1);
      expect(firstPayment.paymentAmount).toBeCloseTo(8791.59, 2);
      expect(firstPayment.principalAmount).toBeCloseTo(7958.26, 2);
      expect(firstPayment.interestAmount).toBeCloseTo(833.33, 2);
      expect(firstPayment.remainingBalance).toBeCloseTo(92041.74, 2);
    });

    it('should throw error for invalid parameters', () => {
      expect(() => calculationService.calculatePaymentSchedule(0, 12, 10)).toThrow(ApiError);
      expect(() => calculationService.calculatePaymentSchedule(100000, 0, 10)).toThrow(ApiError);
      expect(() => calculationService.calculatePaymentSchedule(100000, 12, -1)).toThrow(ApiError);
    });
  });

  describe('calculateMaxAmount', () => {
    it('should calculate correct max amount', () => {
      const result = calculationService.calculateMaxAmount(50000, 20000, 12, 10);
      
      expect(result.maxAmount).toBeGreaterThan(0);
      expect(result.monthlyPayment).toBeLessThanOrEqual(30000); // 60% от дохода
      expect(result.totalAmount).toBeGreaterThan(result.maxAmount);
      expect(result.overpayment).toBeGreaterThan(0);
    });

    it('should throw error for invalid parameters', () => {
      expect(() => calculationService.calculateMaxAmount(0, 20000, 12, 10)).toThrow(ApiError);
      expect(() => calculationService.calculateMaxAmount(50000, -1, 12, 10)).toThrow(ApiError);
      expect(() => calculationService.calculateMaxAmount(50000, 20000, 0, 10)).toThrow(ApiError);
      expect(() => calculationService.calculateMaxAmount(50000, 20000, 12, -1)).toThrow(ApiError);
    });
  });
});
```

#### errorHandler.test
```javascript
import { handleApiError } from '../errorHandler';

describe('errorHandler', () => {
  it('should handle API error with message', () => {
    const error = {
      response: {
        status: 400,
        data: {
          message: 'Invalid input'
        }
      }
    };

    expect(() => handleApiError(error)).toThrow('Invalid input');
  });

  it('should handle API error without message', () => {
    const error = {
      response: {
        status: 500,
        data: {}
      }
    };

    expect(() => handleApiError(error)).toThrow('Произошла ошибка при выполнении запроса');
  });

  it('should handle network error', () => {
    const error = {
      message: 'Network error'
    };

    expect(() => handleApiError(error)).toThrow('Ошибка сети. Проверьте подключение к интернету');
  });

  it('should handle unauthorized error', () => {
    const error = {
      response: {
        status: 401,
        data: {
          message: 'Unauthorized'
        }
      }
    };

    expect(() => handleApiError(error)).toThrow('Необходима авторизация');
  });

  it('should handle forbidden error', () => {
    const error = {
      response: {
        status: 403,
        data: {
          message: 'Forbidden'
        }
      }
    };

    expect(() => handleApiError(error)).toThrow('Доступ запрещен');
  });

  it('should handle not found error', () => {
    const error = {
      response: {
        status: 404,
        data: {
          message: 'Not found'
        }
      }
    };

    expect(() => handleApiError(error)).toThrow('Запрашиваемый ресурс не найден');
  });

  it('should handle validation error', () => {
    const error = {
      response: {
        status: 422,
        data: {
          message: 'Validation failed',
          errors: {
            email: ['Invalid email format'],
            password: ['Password is too short']
          }
        }
      }
    };

    expect(() => handleApiError(error)).toThrow('Ошибка валидации: Invalid email format, Password is too short');
  });

  it('should handle conflict error', () => {
    const error = {
      response: {
        status: 409,
        data: {
          message: 'Conflict'
        }
      }
    };

    expect(() => handleApiError(error)).toThrow('Конфликт данных');
  });

  it('should handle server error', () => {
    const error = {
      response: {
        status: 500,
        data: {
          message: 'Internal server error'
        }
      }
    };

    expect(() => handleApiError(error)).toThrow('Внутренняя ошибка сервера');
  });

  it('should handle unknown error', () => {
    const error = {};

    expect(() => handleApiError(error)).toThrow('Произошла неизвестная ошибка');
  });
});
```

#### formatters.test
```javascript
import { formatCurrency, formatDate, formatDateTime } from '../formatters';

describe('formatters', () => {
  describe('formatCurrency', () => {
    it('should format positive numbers', () => {
      expect(formatCurrency(1000)).toBe('1 000,00 BYN');
      expect(formatCurrency(1234.56)).toBe('1 234,56 BYN');
      expect(formatCurrency(1000000)).toBe('1 000 000,00 BYN');
    });

    it('should format negative numbers', () => {
      expect(formatCurrency(-1000)).toBe('-1 000,00 BYN');
      expect(formatCurrency(-1234.56)).toBe('-1 234,56 BYN');
    });

    it('should format zero', () => {
      expect(formatCurrency(0)).toBe('0,00 BYN');
    });

    it('should handle string inputs', () => {
      expect(formatCurrency('1000')).toBe('1 000,00 BYN');
      expect(formatCurrency('1234.56')).toBe('1 234,56 BYN');
    });

    it('should handle invalid inputs', () => {
      expect(formatCurrency('invalid')).toBe('0,00 BYN');
      expect(formatCurrency(null)).toBe('0,00 BYN');
      expect(formatCurrency(undefined)).toBe('0,00 BYN');
    });
  });

  describe('formatDate', () => {
    it('should format date string', () => {
      expect(formatDate('2024-03-15')).toBe('15.03.2024');
    });

    it('should format Date object', () => {
      expect(formatDate(new Date('2024-03-15'))).toBe('15.03.2024');
    });

    it('should handle invalid inputs', () => {
      expect(formatDate('invalid')).toBe('Invalid Date');
      expect(formatDate(null)).toBe('Invalid Date');
      expect(formatDate(undefined)).toBe('Invalid Date');
    });
  });

  describe('formatDateTime', () => {
    it('should format date-time string', () => {
      expect(formatDateTime('2024-03-15T14:30:00')).toBe('15.03.2024 14:30');
    });

    it('should format Date object', () => {
      expect(formatDateTime(new Date('2024-03-15T14:30:00'))).toBe('15.03.2024 14:30');
    });

    it('should handle single-digit hours and minutes', () => {
      expect(formatDateTime('2024-03-15T09:05:00')).toBe('15.03.2024 09:05');
    });

    it('should handle invalid inputs', () => {
      expect(formatDateTime('invalid')).toBe('Invalid Date');
      expect(formatDateTime(null)).toBe('Invalid Date');
      expect(formatDateTime(undefined)).toBe('Invalid Date');
    });
  });
});
```

#### validators.test
```javascript
import { validateEmail, validatePassword, validateAmount, validateTerm } from '../validators';

describe('validators', () => {
  describe('validateEmail', () => {
    it('should validate correct email', () => {
      expect(validateEmail('test@example.com')).toBe(true);
      expect(validateEmail('user.name@domain.co.uk')).toBe(true);
      expect(validateEmail('user+tag@example.com')).toBe(true);
    });

    it('should reject invalid email', () => {
      expect(validateEmail('test@')).toBe(false);
      expect(validateEmail('@example.com')).toBe(false);
      expect(validateEmail('test@example')).toBe(false);
      expect(validateEmail('test@.com')).toBe(false);
      expect(validateEmail('test@example..com')).toBe(false);
      expect(validateEmail('test example.com')).toBe(false);
    });

    it('should handle empty or undefined input', () => {
      expect(validateEmail('')).toBe(false);
      expect(validateEmail(null)).toBe(false);
      expect(validateEmail(undefined)).toBe(false);
    });
  });

  describe('validatePassword', () => {
    it('should validate correct password', () => {
      expect(validatePassword('Password123')).toBe(true);
      expect(validatePassword('P@ssw0rd')).toBe(true);
      expect(validatePassword('LongPassword123!')).toBe(true);
    });

    it('should reject invalid password', () => {
      expect(validatePassword('short')).toBe(false);
      expect(validatePassword('password')).toBe(false);
      expect(validatePassword('PASSWORD')).toBe(false);
      expect(validatePassword('12345678')).toBe(false);
      expect(validatePassword('Password')).toBe(false);
    });

    it('should handle empty or undefined input', () => {
      expect(validatePassword('')).toBe(false);
      expect(validatePassword(null)).toBe(false);
      expect(validatePassword(undefined)).toBe(false);
    });
  });

  describe('validateAmount', () => {
    it('should validate correct amount', () => {
      expect(validateAmount(1000)).toBe(true);
      expect(validateAmount(1000000)).toBe(true);
      expect(validateAmount(1234.56)).toBe(true);
    });

    it('should reject invalid amount', () => {
      expect(validateAmount(-1000)).toBe(false);
      expect(validateAmount(0)).toBe(false);
      expect(validateAmount('invalid')).toBe(false);
    });

    it('should handle empty or undefined input', () => {
      expect(validateAmount('')).toBe(false);
      expect(validateAmount(null)).toBe(false);
      expect(validateAmount(undefined)).toBe(false);
    });
  });

  describe('validateTerm', () => {
    it('should validate correct term', () => {
      expect(validateTerm(1)).toBe(true);
      expect(validateTerm(12)).toBe(true);
      expect(validateTerm(60)).toBe(true);
    });

    it('should reject invalid term', () => {
      expect(validateTerm(-1)).toBe(false);
      expect(validateTerm(0)).toBe(false);
      expect(validateTerm(61)).toBe(false);
      expect(validateTerm('invalid')).toBe(false);
    });

    it('should handle empty or undefined input', () => {
      expect(validateTerm('')).toBe(false);
      expect(validateTerm(null)).toBe(false);
      expect(validateTerm(undefined)).toBe(false);
    });
  });
});
```

### Интеграционное тестирование
```javascript
import request from 'supertest';
import app from '../app'; 
import db from '../db';   
describe('Integration Tests', () => {

  let clientToken;
  let adminToken;

  beforeAll(async () => {
    // Авторизация клиента
    const clientLogin = await request(app)
      .post('/auth/login')
      .send({ email: 'client@example.com', password: 'password123' });
    clientToken = clientLogin.body.token;

    // Авторизация администратора
    const adminLogin = await request(app)
      .post('/auth/login')
      .send({ email: 'admin@example.com', password: 'adminpass' });
    adminToken = adminLogin.body.token;
  });

  it('Клиент создает рассрочку и администратор подтверждает её', async () => {
    // Клиент создаёт рассрочку
    const createRes = await request(app)
      .post('/installments')
      .set('Authorization', `Bearer ${clientToken}`)
      .send({
        amount: 100000,
        term: 12,
        rate: 10
      });

    expect(createRes.statusCode).toBe(201);
    const installmentId = createRes.body.id;

    // Администратор подтверждает рассрочку
    const approveRes = await request(app)
      .patch(`/installments/${installmentId}/approve`)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(approveRes.statusCode).toBe(200);
    expect(approveRes.body.status).toBe('Одобрено');
  });

  it('Клиент выполняет оплату по активной рассрочке', async () => {
    // Получаем рассрочки клиента
    const listRes = await request(app)
      .get('/installments')
      .set('Authorization', `Bearer ${clientToken}`);
    const activeInstallment = listRes.body.find(r => r.status === 'Одобрено');

    // Выполняем оплату
    const paymentRes = await request(app)
      .post(`/installments/${activeInstallment.id}/pay`)
      .set('Authorization', `Bearer ${clientToken}`)
      .send({ amount: activeInstallment.monthlyPayment });

    expect(paymentRes.statusCode).toBe(200);
    expect(paymentRes.body.message).toBe('Платёж успешно выполнен');
  });

  it('Администратор создаёт и редактирует шаблон рассрочки', async () => {
    // Создание шаблона
    const createTemplateRes = await request(app)
      .post('/templates')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        title: 'Базовый шаблон',
        amount: 50000,
        term: 6,
        rate: 5
      });

    expect(createTemplateRes.statusCode).toBe(201);
    const templateId = createTemplateRes.body.id;

    // Редактирование шаблона
    const editTemplateRes = await request(app)
      .put(`/templates/${templateId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        title: 'Обновлённый шаблон',
        amount: 60000,
        term: 6,
        rate: 6
      });

    expect(editTemplateRes.statusCode).toBe(200);
    expect(editTemplateRes.body.title).toBe('Обновлённый шаблон');
  });
});
```

## Рекомендации по безопасности

1. Регулярно обновляйте зависимости для устранения уязвимостей
2. Используйте HTTPS для всех соединений
3. Применяйте принцип наименьших привилегий
4. Регулярно проводите аудит безопасности
5. Следите за журналами безопасности
6. Используйте многофакторную аутентификацию для административного доступа 

## Контакты
Автор: viktoria.sidorchuk@19gmail.com
