<?php

declare(strict_types=1);

final class Pagination
{
    public readonly int $page;
    public readonly int $perPage;
    public readonly int $total;
    public readonly int $totalPages;

    public function __construct(int $total, int $requestedPage = 1, int $perPage = 20)
    {
        $this->total = max(0, $total);
        $this->perPage = max(1, min(100, $perPage));
        $this->totalPages = max(1, (int) ceil($this->total / $this->perPage));
        $this->page = max(1, min($requestedPage, $this->totalPages));
    }

    public function offset(): int
    {
        return ($this->page - 1) * $this->perPage;
    }

    public function from(): int
    {
        return $this->total === 0 ? 0 : $this->offset() + 1;
    }

    public function to(): int
    {
        return min($this->total, $this->offset() + $this->perPage);
    }

    public function url(int $page): string
    {
        $query = [];
        foreach ($_GET as $key => $value) {
            if (is_string($key) && is_string($value) && $value !== '') {
                $query[$key] = $value;
            }
        }
        $query['page'] = max(1, min($page, $this->totalPages));
        return '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }
}
